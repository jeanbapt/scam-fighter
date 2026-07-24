"""Write-once, content-addressed evidence vault.

Stores raw ``.eml`` bytes under ``SHA-256`` paths and refuses to overwrite an
existing object with different content. This is the chain-of-custody substrate
for complaint packs (see :mod:`scamfighter_core.pack`).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VaultError(Exception):
    """Base class for vault failures."""


class VaultConflict(VaultError):
    """Raised when a write would overwrite an existing object with different content."""


@dataclass(frozen=True)
class VaultObject:
    """One content-addressed evidence blob."""

    sha256: str
    path: Path
    size: int
    stored_at: str
    already_present: bool = False


def _require_sha256(sha256: str) -> str:
    if not _SHA256_RE.fullmatch(sha256):
        raise VaultError(f"invalid sha256 digest: {sha256!r}")
    return sha256


class EvidenceVault:
    """Filesystem vault: ``root/by-hash/ab/cd/<sha256>/{message.eml,meta.json}``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._by_hash = root / "by-hash"
        self._by_hash.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def object_dir(self, sha256: str) -> Path:
        digest = _require_sha256(sha256)
        return self._by_hash / digest[:2] / digest[2:4] / digest

    def put_eml(self, data: bytes, *, source_name: str = "") -> VaultObject:
        """Store raw RFC 822 bytes write-once. Idempotent for identical content."""
        if not data:
            raise VaultError("refusing to store empty evidence")
        sha = self.hash_bytes(data)
        dest = self.object_dir(sha)
        eml_path = dest / "message.eml"
        meta_path = dest / "meta.json"
        now = datetime.now(UTC).isoformat()

        if eml_path.exists():
            existing = eml_path.read_bytes()
            if existing != data:
                raise VaultConflict(f"hash collision or tamper for {sha}")
            return VaultObject(
                sha256=sha,
                path=eml_path,
                size=len(data),
                stored_at=json.loads(meta_path.read_text(encoding="utf-8")).get("stored_at", now)
                if meta_path.exists()
                else now,
                already_present=True,
            )

        dest.mkdir(parents=True, exist_ok=False)
        # Write to a temp name then rename for atomicity within the directory.
        tmp = dest / "message.eml.tmp"
        tmp.write_bytes(data)
        tmp.replace(eml_path)
        meta = {
            "sha256": sha,
            "size": len(data),
            "stored_at": now,
            "source_name": source_name,
            "content_type": "message/rfc822",
        }
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return VaultObject(
            sha256=sha,
            path=eml_path,
            size=len(data),
            stored_at=now,
            already_present=False,
        )

    def put_file(self, path: Path) -> VaultObject:
        return self.put_eml(path.read_bytes(), source_name=path.name)

    def get(self, sha256: str) -> Path:
        path = self.object_dir(sha256) / "message.eml"
        if not path.exists():
            raise VaultError(f"no evidence object for {sha256}")
        return path

    def meta(self, sha256: str) -> dict[str, object]:
        path = self.object_dir(sha256) / "meta.json"
        if not path.exists():
            raise VaultError(f"no meta for {sha256}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise VaultError("corrupt meta.json")
        return data


def vault_object_as_dict(obj: VaultObject) -> dict[str, object]:
    d = asdict(obj)
    d["path"] = str(obj.path)
    return d
