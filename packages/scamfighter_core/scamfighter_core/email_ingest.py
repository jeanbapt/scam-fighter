"""Deterministic email + indicator parsing.

This is the first, most reliable layer of the pipeline (see the models section of
``docs/IMPLEMENTATION_PLAN.md``): pure parsing and regex extraction, no LLM. It
debunks the classic "I sent this from your own account" sextortion claim by
reading the authentication results and origin, and it pulls indicators (crypto
addresses, URLs, IPs) that never need a model.

Everything here treats input as hostile: we parse, we never fetch URLs or execute
attachments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.message import EmailMessage

# Indicators. Deterministic and auditable — no model involved.
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Authentication-Results verdicts.
_SPF_RE = re.compile(r"\bspf=(\w+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"\bdkim=(\w+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)

# RFC 1918 / loopback ranges we treat as internal hops, not the true origin.
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.")


@dataclass(frozen=True)
class AuthResults:
    """Authentication verdicts pulled from the Authentication-Results header."""

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None

    @property
    def all_failing(self) -> bool:
        """True when nothing authenticates the sender (a spoofing tell)."""
        passing = {"pass"}
        verdicts = [v for v in (self.spf, self.dkim, self.dmarc) if v is not None]
        return bool(verdicts) and not any(v.lower() in passing for v in verdicts)


@dataclass(frozen=True)
class Indicators:
    """Deterministically extracted indicators of compromise."""

    bitcoin_addresses: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    public_ips: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedEmail:
    """Typed view of a parsed message. No network side effects to build this."""

    from_addr: str
    to_addr: str
    subject: str
    date: str
    message_id: str
    headers: dict[str, str]
    received_chain: tuple[str, ...]
    auth: AuthResults
    body: str
    indicators: Indicators
    is_self_addressed: bool = field(default=False)


def _addr(value: str | None) -> str:
    if not value:
        return ""
    # "Name <a@b>" -> a@b ; bare address passes through.
    m = re.search(r"<([^>]+)>", value)
    return (m.group(1) if m else value).strip().lower()


def _public_ips(raw: str) -> tuple[str, ...]:
    seen: list[str] = []
    for ip in _IPV4_RE.findall(raw):
        if ip.startswith(_PRIVATE_PREFIXES):
            continue
        if ip not in seen:
            seen.append(ip)
    return tuple(seen)


def _dedupe(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    seen: list[str] = []
    for match in pattern.findall(text):
        if match not in seen:
            seen.append(match)
    return tuple(seen)


def parse_eml(raw: str) -> ParsedEmail:
    """Parse a raw RFC 822 message into a typed :class:`ParsedEmail`."""
    msg: EmailMessage = message_from_string(raw, policy=policy.default)  # type: ignore[assignment]

    headers = {k: str(v) for k, v in msg.items()}
    auth_raw = " ".join(v for k, v in msg.items() if k.lower() == "authentication-results")

    def _verdict(pattern: re.Pattern[str]) -> str | None:
        m = pattern.search(auth_raw)
        return m.group(1).lower() if m else None

    auth = AuthResults(
        spf=_verdict(_SPF_RE),
        dkim=_verdict(_DKIM_RE),
        dmarc=_verdict(_DMARC_RE),
    )

    if msg.is_multipart():
        parts = [p for p in msg.walk() if p.get_content_type() == "text/plain"]
        body = "\n".join(p.get_content() for p in parts) if parts else ""
    else:
        body = msg.get_content() if msg.get_content_maintype() == "text" else ""

    from_addr = _addr(msg.get("From"))
    to_addr = _addr(msg.get("To"))

    indicators = Indicators(
        bitcoin_addresses=_dedupe(_BTC_RE, body),
        urls=_dedupe(_URL_RE, body),
        public_ips=_public_ips(raw),
    )

    return ParsedEmail(
        from_addr=from_addr,
        to_addr=to_addr,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        headers=headers,
        received_chain=tuple(str(v) for k, v in msg.items() if k.lower() == "received"),
        auth=auth,
        body=body,
        indicators=indicators,
        is_self_addressed=bool(from_addr) and from_addr == to_addr,
    )


def defang(indicator: str) -> str:
    """Render an indicator unclickable for safe display in reports/logs."""
    return indicator.replace("http", "hxxp").replace(".", "[.]")
