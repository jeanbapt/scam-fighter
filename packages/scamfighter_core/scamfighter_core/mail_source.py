"""Mail sources: where raw messages come from.

Phase 1 sources, all read-only, ordered by least privilege (see
``docs/MACOS_MAIL.md``):

* :class:`FolderSource` — reads ``.eml``/``.emlx`` files from a directory you
  control (a drop/watch folder). **No special permission**: you export only the
  suspect messages. Recommended default.
* :class:`ImapSource` — connects to an IMAP account read-only. Scoped to one
  mailbox over the network; no disk permissions.
* :class:`MacMailSource` — reads Apple Mail's on-disk ``.emlx`` store directly.
  Highest fidelity, but the process needs macOS **Full Disk Access**, which is
  coarse (app-scoped, not folder-scoped). Prefer a dedicated signed helper over
  granting FDA to your daily terminal/IDE.

All yield :class:`~scamfighter_core.email_ingest.ParsedEmail`. None fetch URLs or
open attachments. Symlinks are never followed; oversized files are skipped.
"""

from __future__ import annotations

import contextlib
import imaplib
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from scamfighter_core.email_ingest import ParsedEmail, parse_eml_bytes

# Refuse to load a single message larger than this (DoS bound).
MAX_MESSAGE_BYTES = 25 * 1024 * 1024


class MessageTooLarge(OSError):
    """Raised when a message file exceeds :data:`MAX_MESSAGE_BYTES`."""


@runtime_checkable
class MailSource(Protocol):
    """A read-only source of parsed messages."""

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        """Yield parsed messages, at most ``limit`` if given."""
        ...


def parse_emlx(raw: bytes) -> bytes:
    """Extract the RFC 822 message bytes from Apple Mail's ``.emlx`` framing.

    An ``.emlx`` file is: a first line with the message byte count, then exactly
    that many bytes of the raw message, then an Apple plist of flags. We return
    just the message bytes so charset headers are preserved for
    :func:`~scamfighter_core.email_ingest.parse_eml_bytes`.
    """
    newline = raw.find(b"\n")
    if newline == -1:
        return raw
    header = raw[:newline].strip()
    try:
        count = int(header)
    except ValueError:
        # Not framed (already a plain message) — return as-is.
        return raw
    return raw[newline + 1 : newline + 1 + count]


def _check_size(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MessageTooLarge(f"cannot stat {path}: {exc}") from exc
    if size > MAX_MESSAGE_BYTES:
        raise MessageTooLarge(f"message exceeds {MAX_MESSAGE_BYTES} bytes: {path} ({size})")


def read_message_file(path: Path) -> bytes:
    """Read a ``.eml`` or ``.emlx`` file as raw RFC 822 bytes (size-capped)."""
    _check_size(path)
    raw = path.read_bytes()
    if path.suffix.lower() == ".emlx":
        return parse_emlx(raw)
    return raw


def _is_safe_under(root: Path, candidate: Path) -> bool:
    """True when ``candidate`` is a real file under ``root`` (no symlink escape)."""
    try:
        if candidate.is_symlink():
            return False
        if not candidate.is_file():
            return False
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        return resolved == root_resolved or root_resolved in resolved.parents
    except OSError:
        return False


class FolderSource:
    """Read ``.eml``/``.emlx`` files from a directory you control (least privilege).

    You decide what lands in the folder (drag from Mail, a Mail rule, an export),
    so no macOS Full Disk Access or account credentials are needed.

    Symlinks are skipped and resolved paths must stay under ``path`` so a planted
    link cannot exfiltrate arbitrary files into the parser.
    """

    def __init__(self, path: Path, *, recursive: bool = True) -> None:
        if not path.exists():
            raise FileNotFoundError(f"folder not found: {path}")
        self.path = path
        self._glob = path.rglob if recursive else path.glob

    def iter_message_paths(self) -> Iterator[Path]:
        seen: set[Path] = set()
        for pattern in ("*.eml", "*.emlx"):
            for p in self._glob(pattern):
                if p in seen:
                    continue
                if not _is_safe_under(self.path, p):
                    continue
                seen.add(p)
                yield p

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        count = 0
        for path in self.iter_message_paths():
            if limit is not None and count >= limit:
                return
            try:
                message = read_message_file(path)
                yield parse_eml_bytes(message)
            except (OSError, ValueError, TypeError, UnicodeError):
                continue
            count += 1


def default_mac_mail_root() -> Path | None:
    """Return the newest ``~/Library/Mail/V*`` directory, or ``None`` if absent."""
    base = Path.home() / "Library" / "Mail"
    if not base.exists():
        return None
    versions = sorted(
        (p for p in base.glob("V*") if p.is_dir()),
        key=lambda p: p.name,
    )
    return versions[-1] if versions else None


class MacMailSource:
    """Read Apple Mail's local ``.emlx`` store (read-only)."""

    def __init__(self, root: Path | None = None) -> None:
        resolved = root if root is not None else default_mac_mail_root()
        if resolved is None:
            raise FileNotFoundError(
                "No Apple Mail store found under ~/Library/Mail (pass root=...)"
            )
        self.root = resolved

    def iter_emlx_paths(self) -> Iterator[Path]:
        for p in sorted(self.root.rglob("*.emlx")):
            if _is_safe_under(self.root, p):
                yield p

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        count = 0
        for path in self.iter_emlx_paths():
            if limit is not None and count >= limit:
                return
            try:
                _check_size(path)
                message = parse_emlx(path.read_bytes())
                yield parse_eml_bytes(message)
            except (OSError, ValueError, TypeError, UnicodeError):
                continue
            count += 1


class ImapSource:
    """Read-only IMAP source (e.g. OVH). Never mutates the mailbox."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        *,
        folder: str = "INBOX",
        port: int = 993,
    ) -> None:
        self._host = host
        self._user = user
        self._password = password
        self._folder = folder
        self._port = port

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        conn = imaplib.IMAP4_SSL(self._host, self._port)
        try:
            conn.login(self._user, self._password)
            # readonly=True: observe-only, never flag messages as read.
            conn.select(self._folder, readonly=True)
            typ, data = conn.search(None, "ALL")
            if typ != "OK" or not data or not data[0]:
                return
            ids = data[0].split()
            if limit is not None:
                ids = ids[-limit:]
            for msg_id in ids:
                typ, msg_data = conn.fetch(msg_id, "(BODY.PEEK[])")
                if typ != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                    continue
                raw = msg_data[0][1]
                if isinstance(raw, bytes):
                    if len(raw) > MAX_MESSAGE_BYTES:
                        continue
                    try:
                        yield parse_eml_bytes(raw)
                    except (ValueError, TypeError, UnicodeError):
                        continue
        finally:
            with contextlib.suppress(imaplib.IMAP4.error, OSError):
                conn.close()
            conn.logout()
