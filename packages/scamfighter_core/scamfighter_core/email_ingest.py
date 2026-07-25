"""Deterministic email + indicator parsing.

This is the first, most reliable layer of the pipeline (see the models section of
``docs/IMPLEMENTATION_PLAN.md``): pure parsing and regex extraction, no LLM. It
debunks the classic "I sent this from your own account" sextortion claim by
reading the authentication results and origin, and it pulls indicators (crypto
addresses, URLs, IPs) that never need a model.

Everything here treats input as hostile: we parse, we never fetch URLs or execute
attachments. Prefer :func:`parse_eml_bytes` so charset headers are respected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes, message_from_string, policy
from email.message import EmailMessage
from html.parser import HTMLParser

# Cap how much body/Received text we scan for indicators (DoS / ReDoS bound).
_INDICATOR_SCAN_BYTES = 256 * 1024
_MAX_RECEIVED_HEADERS = 64

# Indicators. Deterministic and auditable — no model involved.
# Bounded quantifiers / character classes avoid catastrophic backtracking.
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]{1,2048}", re.IGNORECASE)
# Octets without leading zeros — avoids Gmail ESMTPS ids like
# ``…sm7718….2026.07.24.20.49.45`` matching as ``07.24.20.49``.
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
_IPV4_RE = re.compile(rf"\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\b")
# SMTP Received convention: client address appears in square brackets.
_BRACKET_IPV4_RE = re.compile(rf"\[((?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET})\]")
_HREF_ATTRS = frozenset({"href", "src", "action", "poster", "data", "formaction"})

# Authentication-Results verdicts.
_SPF_RE = re.compile(r"\bspf=(\w+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"\bdkim=(\w+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)

# RFC 1918 / loopback / link-local — not the true origin. CGNAT handled in
# :func:`_is_private_ip`.
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


class _HTMLTextExtractor(HTMLParser):
    """Stdlib-only tag stripper: no rendering, no network, no JS.

    Also collects ``http(s)`` URLs from link-like attributes (``href``/``src``/…),
    because multipart/alternative mails often put the CTA only in the HTML part
    while the text/plain twin has a bare label like "Me connecter".
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._urls: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip = True
            return
        for name, value in attrs:
            if name.lower() not in _HREF_ATTRS or not value:
                continue
            candidate = value.strip()
            if candidate.lower().startswith(("http://", "https://")):
                self._urls.append(candidate)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        return "\n".join(self._chunks)

    def urls(self) -> tuple[str, ...]:
        seen: list[str] = []
        for url in self._urls:
            if url not in seen:
                seen.append(url)
        return tuple(seen)


def html_to_text(html: str) -> str:
    """Strip tags from HTML mail for indicator scanning (never fetch, never render)."""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return parser.text()


def html_urls(html: str) -> tuple[str, ...]:
    """Collect ``http(s)`` URLs from HTML attributes only (never fetch)."""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return _dedupe(_URL_RE, html)
    return parser.urls()


def _addr(value: str | None) -> str:
    if not value:
        return ""
    # "Name <a@b>" -> a@b ; bare address passes through.
    m = re.search(r"<([^>]+)>", value)
    return (m.group(1) if m else value).strip().lower()


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    # CGNAT 100.64.0.0/10
    if ip.startswith("100."):
        try:
            second = int(ip.split(".", 2)[1])
        except (IndexError, ValueError):
            return False
        return 64 <= second <= 127
    return False


def _public_ips(text: str) -> tuple[str, ...]:
    """Prefer bracketed IPs from the Received chain (SMTP convention).

    Falling back to a free-text IPv4 scan still rejects leading-zero octets so
    timestamp fragments inside Gmail ESMTPS ids are not treated as origins.
    """
    clipped = text[:_INDICATOR_SCAN_BYTES]
    bracketed = _BRACKET_IPV4_RE.findall(clipped)
    candidates = bracketed if bracketed else _IPV4_RE.findall(clipped)
    seen: list[str] = []
    for ip in candidates:
        if _is_private_ip(ip):
            continue
        if ip not in seen:
            seen.append(ip)
    return tuple(seen)


def _dedupe(pattern: re.Pattern[str], text: str) -> tuple[str, ...]:
    seen: list[str] = []
    for match in pattern.findall(text[:_INDICATOR_SCAN_BYTES]):
        if match not in seen:
            seen.append(match)
    return tuple(seen)


def _extract_body_and_html(msg: EmailMessage) -> tuple[str, tuple[str, ...]]:
    """Prefer text/plain for body text; always return HTML parts for href scan.

    Never render or fetch. HTML is kept even when plain exists because phishing
    CTAs ("Me connecter") often live only in ``<a href=...>``.
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    plain_parts.append(str(part.get_content()))
                except Exception:  # noqa: S112 — skip undecodable hostile parts
                    continue
            elif ctype == "text/html":
                try:
                    html_parts.append(str(part.get_content()))
                except Exception:  # noqa: S112 — skip undecodable hostile parts
                    continue
    else:
        ctype = msg.get_content_type()
        try:
            content = str(msg.get_content()) if msg.get_content_maintype() == "text" else ""
        except Exception:
            content = ""
        if ctype == "text/html":
            html_parts.append(content)
        elif content:
            plain_parts.append(content)

    html = tuple(html_parts)
    if plain_parts:
        return "\n".join(plain_parts), html
    if html:
        return html_to_text("\n".join(html)), html
    return "", ()


def _from_message(msg: EmailMessage) -> ParsedEmail:
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

    received_list: list[str] = []
    for k, v in msg.items():
        if k.lower() != "received":
            continue
        received_list.append(str(v))
        if len(received_list) >= _MAX_RECEIVED_HEADERS:
            break
    received = tuple(received_list)
    body, html_parts = _extract_body_and_html(msg)

    from_addr = _addr(msg.get("From"))
    to_addr = _addr(msg.get("To"))

    urls: list[str] = list(_dedupe(_URL_RE, body))
    for blob in html_parts:
        for url in html_urls(blob):
            if url not in urls:
                urls.append(url)

    # Origin IPs come from the Received chain only — not the whole raw message
    # (which would also pick up IPs quoted in the scam body).
    indicators = Indicators(
        bitcoin_addresses=_dedupe(_BTC_RE, body),
        urls=tuple(urls),
        public_ips=_public_ips("\n".join(received)),
    )

    return ParsedEmail(
        from_addr=from_addr,
        to_addr=to_addr,
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        headers=headers,
        received_chain=received,
        auth=auth,
        body=body,
        indicators=indicators,
        is_self_addressed=bool(from_addr) and from_addr == to_addr,
    )


def parse_eml_bytes(raw: bytes) -> ParsedEmail:
    """Parse raw RFC 822 bytes, respecting charset headers (preferred entry point)."""
    msg = message_from_bytes(raw, policy=policy.default)
    if not isinstance(msg, EmailMessage):
        raise TypeError("expected EmailMessage from message_from_bytes")
    return _from_message(msg)


def parse_eml(raw: str) -> ParsedEmail:
    """Parse a raw RFC 822 message already decoded as text.

    Prefer :func:`parse_eml_bytes` when you have the original bytes so non-UTF-8
    charsets are preserved.
    """
    msg = message_from_string(raw, policy=policy.default)
    if not isinstance(msg, EmailMessage):
        raise TypeError("expected EmailMessage from message_from_string")
    return _from_message(msg)


def defang(indicator: str) -> str:
    """Render an indicator unclickable for safe display in reports/logs."""
    return indicator.replace("http", "hxxp").replace(".", "[.]")
