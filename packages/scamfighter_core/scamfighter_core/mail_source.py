"""Mail sources: where raw messages come from.

Phase 1 supports two local-first sources, both read-only:

* :class:`MacMailSource` — reads Apple Mail's on-disk ``.emlx`` store directly. No
  account credentials needed, but the process needs macOS **Full Disk Access** to
  read ``~/Library/Mail`` (see ``docs/MACOS_MAIL.md``).
* :class:`ImapSource` — connects to an IMAP account (e.g. OVH) read-only.

Both yield :class:`~scamfighter_core.email_ingest.ParsedEmail`. Neither fetches
URLs or opens attachments.
"""

from __future__ import annotations

import imaplib
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from scamfighter_core.email_ingest import ParsedEmail, parse_eml


@runtime_checkable
class MailSource(Protocol):
    """A read-only source of parsed messages."""

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        """Yield parsed messages, at most ``limit`` if given."""
        ...


def parse_emlx(raw: bytes) -> str:
    """Extract the RFC 822 message from Apple Mail's ``.emlx`` framing.

    An ``.emlx`` file is: a first line with the message byte count, then exactly
    that many bytes of the raw message, then an Apple plist of flags. We return
    just the message text.
    """
    newline = raw.find(b"\n")
    if newline == -1:
        return raw.decode("utf-8", errors="replace")
    header = raw[:newline].strip()
    try:
        count = int(header)
    except ValueError:
        # Not framed (already a plain message) — return as-is.
        return raw.decode("utf-8", errors="replace")
    message = raw[newline + 1 : newline + 1 + count]
    return message.decode("utf-8", errors="replace")


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
        yield from sorted(self.root.rglob("*.emlx"))

    def iter_parsed(self, *, limit: int | None = None) -> Iterator[ParsedEmail]:
        count = 0
        for path in self.iter_emlx_paths():
            if limit is not None and count >= limit:
                return
            try:
                message = parse_emlx(path.read_bytes())
            except OSError:
                continue
            yield parse_eml(message)
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
                    yield parse_eml(raw.decode("utf-8", errors="replace"))
        finally:
            try:
                conn.close()
            except (imaplib.IMAP4.error, OSError):
                pass
            conn.logout()
