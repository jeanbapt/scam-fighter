"""Filing helpers: pack load, mailto drafts, Spamhaus submit (confirm-gated).

Observe-only by default. Network submit requires an explicit confirmation token.
Never fetches URLs found inside scam mail.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any

# Spamhaus Submission Portal — raw email max 150 KiB per their docs.
_SPAMHAUS_EMAIL_MAX = 150 * 1024
_SPAMHAUS_BASE = "https://submit.spamhaus.org/portal/api/v1"


@dataclass(frozen=True)
class PackSnapshot:
    """Minimal pack view for MCP tools (no full .eml body by default)."""

    case_id: str
    directory: Path
    sha256: str
    connecting_ip: str | None
    bitcoin_addresses: tuple[str, ...]
    public_ips: tuple[str, ...]
    abuse_emails: tuple[str, ...]
    meta: dict[str, Any]
    has_message_eml: bool
    complaint_fr_excerpt: str
    provenance_notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "directory": str(self.directory),
            "sha256": self.sha256,
            "connecting_ip": self.connecting_ip,
            "bitcoin_addresses": list(self.bitcoin_addresses),
            "public_ips": list(self.public_ips),
            "abuse_emails": list(self.abuse_emails),
            "has_message_eml": self.has_message_eml,
            "complaint_fr_excerpt": self.complaint_fr_excerpt,
            "provenance_notes": list(self.provenance_notes),
            "meta_keys": sorted(self.meta.keys()),
        }


@dataclass
class _PendingAction:
    action: str
    payload: dict[str, Any]
    created_at: float
    confirmed: bool = False


@dataclass
class ApprovalGate:
    """In-memory one-shot confirmations for submit actions."""

    ttl_seconds: float = 900.0
    _pending: dict[str, _PendingAction] = field(default_factory=dict)

    def request(self, action: str, payload: dict[str, Any]) -> str:
        token = secrets.token_urlsafe(24)
        self._pending[token] = _PendingAction(
            action=action, payload=payload, created_at=time.time()
        )
        return token

    def confirm(self, token: str) -> dict[str, Any]:
        item = self._require(token)
        item.confirmed = True
        return {"token": token, "action": item.action, "confirmed": True}

    def consume(self, token: str, *, expected_action: str) -> dict[str, Any]:
        item = self._require(token)
        if not item.confirmed:
            raise PermissionError("action not confirmed; call confirm(token) first")
        if item.action != expected_action:
            raise PermissionError(f"token is for {item.action!r}, not {expected_action!r}")
        payload = item.payload
        del self._pending[token]
        return payload

    def peek(self, token: str) -> dict[str, Any]:
        item = self._require(token)
        return {
            "token": token,
            "action": item.action,
            "confirmed": item.confirmed,
            "payload_keys": sorted(item.payload.keys()),
            "age_seconds": round(time.time() - item.created_at, 1),
        }

    def _require(self, token: str) -> _PendingAction:
        item = self._pending.get(token)
        if item is None:
            raise KeyError("unknown or already consumed approval token")
        if time.time() - item.created_at > self.ttl_seconds:
            del self._pending[token]
            raise KeyError("approval token expired")
        return item


_GATE = ApprovalGate()


def approval_gate() -> ApprovalGate:
    return _GATE


def resolve_packs_root(override: Path | None = None) -> Path:
    raw = os.environ.get("SCAMFIGHTER_PACKS", "~/ScamFighter/packs")
    return (override or Path(raw)).expanduser().resolve()


def load_pack(path_or_case: str | Path) -> PackSnapshot:
    """Load an existing evidence pack by directory path or case_id under packs root."""
    packs_root = resolve_packs_root()
    raw = Path(path_or_case).expanduser()
    if raw.is_dir() and (raw / "meta.json").is_file():
        # Operator-chosen absolute/relative directory that already looks like a pack.
        pack_dir = raw.resolve()
    else:
        case = str(path_or_case)
        if "/" in case or "\\" in case or ".." in case or case in {".", ""}:
            raise ValueError(f"invalid case_id (path separators / '..' forbidden): {case!r}")
        candidate = (packs_root / case).resolve()
        try:
            candidate.relative_to(packs_root)
        except ValueError as exc:
            raise PermissionError(
                f"case_id resolves outside packs root {packs_root}: {case!r}"
            ) from exc
        if not (candidate / "meta.json").is_file():
            raise FileNotFoundError(f"pack not found: {path_or_case}")
        pack_dir = candidate

    meta = json.loads((pack_dir / "meta.json").read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError("meta.json must be an object")

    analysis_raw = meta.get("analysis")
    analysis: dict[str, Any] = analysis_raw if isinstance(analysis_raw, dict) else {}
    abuse: list[str] = []
    prov_path = pack_dir / "provenance.json"
    if prov_path.is_file():
        prov = json.loads(prov_path.read_text(encoding="utf-8"))
        if isinstance(prov, dict):
            for row in prov.get("ips") or []:
                if isinstance(row, dict):
                    for em in row.get("abuse_emails") or []:
                        if isinstance(em, str) and em not in abuse:
                            abuse.append(em)

    fr = pack_dir / "complaint_fr.md"
    excerpt = ""
    if fr.is_file():
        text = fr.read_text(encoding="utf-8")
        excerpt = text[:1200] + ("…" if len(text) > 1200 else "")

    notes_raw = meta.get("provenance_notes")
    notes: list[Any] = notes_raw if isinstance(notes_raw, list) else []
    return PackSnapshot(
        case_id=str(meta.get("case_id") or pack_dir.name),
        directory=pack_dir,
        sha256=str(meta.get("sha256") or ""),
        connecting_ip=meta.get("connecting_ip")
        if isinstance(meta.get("connecting_ip"), str)
        else None,
        bitcoin_addresses=tuple(
            str(x) for x in (analysis.get("bitcoin_addresses") or []) if isinstance(x, str)
        ),
        public_ips=tuple(str(x) for x in (analysis.get("public_ips") or []) if isinstance(x, str)),
        abuse_emails=tuple(abuse),
        meta=meta,
        has_message_eml=(pack_dir / "message.eml").is_file(),
        complaint_fr_excerpt=excerpt,
        provenance_notes=tuple(str(n) for n in notes),
    )


def draft_abuse_mailto(
    pack: PackSnapshot,
    *,
    to: str,
    lang: str = "fr",
) -> dict[str, Any]:
    """Build an RFC822 draft attaching message.eml — does not send."""
    body_path = pack.directory / (
        f"complaint_{lang}.md" if lang in {"fr", "en"} else "complaint_en.md"
    )
    body = (
        body_path.read_text(encoding="utf-8") if body_path.is_file() else pack.complaint_fr_excerpt
    )
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = f"[ScamFighter] Abuse report {pack.case_id} sha256={pack.sha256[:16]}"
    msg.set_content(body)
    eml = pack.directory / "message.eml"
    if eml.is_file():
        msg.add_attachment(
            eml.read_bytes(),
            maintype="message",
            subtype="rfc822",
            filename="message.eml",
        )
    draft_path = pack.directory / f"draft_mailto_{_safe_local(to)}.eml"
    draft_path.write_bytes(msg.as_bytes())
    return {
        "to": to,
        "subject": msg["Subject"],
        "draft_path": str(draft_path),
        "attached_message_eml": eml.is_file(),
        "note": "Draft written to disk. ScamFighter does not send mail.",
    }


def _safe_local(addr: str) -> str:
    local = addr.split("@", 1)[0]
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in local)[:40] or "abuse"


def prepare_spamhaus_email(pack: PackSnapshot, *, reason: str) -> dict[str, Any]:
    """Build Spamhaus raw-email submission payload (dry-run)."""
    eml = pack.directory / "message.eml"
    if not eml.is_file():
        raise FileNotFoundError("message.eml missing from pack")
    raw = eml.read_bytes()
    if len(raw) > _SPAMHAUS_EMAIL_MAX:
        raise ValueError(f"message.eml exceeds Spamhaus {_SPAMHAUS_EMAIL_MAX} byte limit")
    # Spamhaus expects a string of raw email; keep ASCII-safe via latin-1 roundtrip
    # for binary-safe transport in JSON (their samples use plain text).
    try:
        raw_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = raw.decode("latin-1")
    payload = {
        "threat_type": "source-of-spam",
        "reason": reason[:255],
        "source": {"object": raw_text},
        "meta": {
            "case_id": pack.case_id,
            "sha256": pack.sha256,
            "connecting_ip": pack.connecting_ip,
            "endpoint": f"{_SPAMHAUS_BASE}/submissions/add/email",
            "dry_run_default": True,
        },
    }
    return {
        "endpoint": f"{_SPAMHAUS_BASE}/submissions/add/email",
        "threat_type": payload["threat_type"],
        "reason": payload["reason"],
        "raw_bytes": len(raw),
        "case_id": pack.case_id,
        "sha256": pack.sha256,
        "_payload": payload,
    }


def request_spamhaus_submit(pack: PackSnapshot, *, reason: str) -> dict[str, Any]:
    prepared = prepare_spamhaus_email(pack, reason=reason)
    token = approval_gate().request("submit_spamhaus_email", prepared["_payload"])
    return {
        "approval_token": token,
        "action": "submit_spamhaus_email",
        "confirmed": False,
        "preview": {k: v for k, v in prepared.items() if k != "_payload"},
        "next": "Call confirm_action(token), then submit_spamhaus_email(token).",
    }


def confirm_action(token: str) -> dict[str, Any]:
    return approval_gate().confirm(token)


def submit_spamhaus_email(token: str, *, dry_run: bool = True) -> dict[str, Any]:
    """Submit to Spamhaus only after confirm.

    Defaults to ``dry_run=True`` (observe-first). Pass ``dry_run=False`` for a live POST
    (requires ``SPAMHAUS_API_TOKEN``).
    """
    payload = approval_gate().consume(token, expected_action="submit_spamhaus_email")
    if dry_run:
        return {
            "status": "dry_run",
            "would_post": f"{_SPAMHAUS_BASE}/submissions/add/email",
            "threat_type": payload.get("threat_type"),
            "reason": payload.get("reason"),
            "case_meta": payload.get("meta"),
        }
    api_token = os.environ.get("SPAMHAUS_API_TOKEN", "").strip()
    if not api_token:
        raise RuntimeError("SPAMHAUS_API_TOKEN is not set")
    body = {
        "threat_type": payload["threat_type"],
        "reason": payload["reason"],
        "source": payload["source"],
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 — https-only, documented API
        f"{_SPAMHAUS_BASE}/submissions/add/email",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "User-Agent": "scamfighter-filing/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
            status = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        return {"status": "error", "http_status": exc.code, "body": err_body[:2000]}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw": raw[:2000]}
    return {"status": "ok", "http_status": status, "response": parsed}


def form_fill_plan(channel: str, pack: PackSnapshot) -> dict[str, Any]:
    """Field map for Playwright MCP — never auto-submits."""
    channel = channel.lower().strip()
    common = {
        "case_id": pack.case_id,
        "sha256": pack.sha256,
        "attach": str(pack.directory / "message.eml"),
        "complaint_fr": str(pack.directory / "complaint_fr.md"),
        "complaint_en": str(pack.directory / "complaint_en.md"),
        "connecting_ip": pack.connecting_ip,
        "bitcoin": list(pack.bitcoin_addresses),
        "auto_submit": False,
        "human_required": True,
    }
    if channel == "ovh_abuse":
        return {
            **common,
            "channel": "ovh_abuse",
            "urls": {
                "fr": "https://www.ovhcloud.com/fr/abuse/",
                "en": "https://www.ovhcloud.com/en/abuse/",
            },
            "suggested_category": "Phishing / Scam",
            "preferred_alt": (
                "fraude@ovh.com + attach message.eml (SMTP draft via draft_abuse_mailto)"
            ),
            "fields": {
                "category": "Phishing / Scam",
                "description": (
                    f"See complaint_fr.md for case {pack.case_id}; SHA-256 {pack.sha256}"
                ),
                "attachment": "message.eml",
            },
        }
    if channel == "pharos":
        return {
            **common,
            "channel": "pharos",
            "urls": {"fr": "https://internet-signalement.gouv.fr/"},
            "note": (
                "Pharos is for illicit *content* reports. Bulk mailbox spam is usually "
                "redirected to signal-spam.fr. Prefer THESEE for sextortion plainte."
            ),
            "fields": {
                "nature": "arnaque / chantage (à vérifier sur le formulaire)",
                "description": pack.complaint_fr_excerpt,
            },
        }
    if channel == "thesee":
        return {
            **common,
            "channel": "thesee",
            "urls": {
                "service_public": "https://www.service-public.gouv.fr/particuliers/vosdroits/N31138",
                "ma_securite": (
                    "https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/"
                    "thesee-arnaques-internet-plainte-en-ligne"
                ),
            },
            "note": "FranceConnect login must be completed by the human operator.",
            "fields": {
                "faits": pack.complaint_fr_excerpt,
                "pieces": ["message.eml", "complaint_fr.md", "MANIFEST.sha256"],
            },
        }
    if channel == "signal_spam":
        return {
            **common,
            "channel": "signal_spam",
            "urls": {"fr": "https://www.signal-spam.fr/"},
            "note": "Consumer UI / browser plugins; no public submit API for individuals.",
            "fields": {"message": "message.eml"},
        }
    raise ValueError(f"unknown channel: {channel!r} (ovh_abuse|pharos|thesee|signal_spam)")
