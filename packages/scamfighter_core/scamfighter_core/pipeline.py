"""End-to-end analysis: source -> parse -> deterministic verdict -> optional summary.

Classification is deterministic on purpose (see ``docs/IMPLEMENTATION_PLAN.md``):

* **Sextortion** — self-addressed spoof + failed auth + crypto demand + phrasing.
* **Phishing** — header irregularities (display-name vs From-domain, self-addressed
  bulk, Message-ID / Return-Path mismatch, off-domain CTA). Auth may *pass*; a
  passing SPF only proves the *sending domain* signed the mail, not that the
  display brand is real.
* **False-positive disambiguation** — trusted notifiers (GitHub, Google, …) often
  put a *person* display name on a platform From address and link to sibling
  CDNs. Those irregularities are recorded, then cleared for scoring when the
  From domain authenticates and CTAs stay in the org family.

The LLM is optional and only drafts a human-readable summary, gated by the
egress guard when it runs in the cloud.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from scamfighter_core.email_ingest import ParsedEmail
from scamfighter_core.llm import ProviderRouter

_SEXTORTION_PHRASES = (
    "recorded you",
    "your camera",
    "masturbat",
    "trojan",
    "rat (remote",
    "sent it from your",
    "from your email account",
    "bitcoin",
    "your device was infected",
)

# Display-name tokens worth comparing to the From domain (skip "Re", "Fwd", …).
_DISPLAY_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{3,}")
_FROM_DISPLAY_RE = re.compile(r'^"?\s*([^"<@]+?)\s*"?\s*<', re.UNICODE)
_MSGID_HOST_RE = re.compile(r"@([^>]+)>?\s*$")
_ADDR_RE = re.compile(r"<([^>]+)>")

# Infrastructure hosts that often appear in Message-ID without matching From
# (Gmail injects SMTPIN_ADDED_MISSING when the client omitted Message-ID).
_INFRA_MSGID_MARKERS = (
    "smtpin_added_missing",
    "mail.gmail.com",
    "mx.google.com",
)

# Registrable domains that send authenticated mail with *person* display names
# (PR authors, Dependabot, "Google", …). Brand-mismatch alone is not phishing.
_TRUSTED_NOTIFIER_REGISTRABLES = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "google.com",
        "gmail.com",
        "microsoft.com",
        "outlook.com",
        "apple.com",
        "icloud.com",
        "linkedin.com",
        "slack.com",
        "stripe.com",
        "amazon.com",
        "paypal.com",
        "dropbox.com",
        "atlassian.com",
        "notion.so",
        "vercel.com",
        "netlify.com",
    }
)

# Sibling CDN / product hosts that share an org with a From domain.
_ORG_FAMILIES: tuple[frozenset[str], ...] = (
    frozenset({"github.com", "githubusercontent.com", "githubassets.com", "github.io"}),
    frozenset(
        {
            "google.com",
            "gmail.com",
            "googlemail.com",
            "youtube.com",
            "ytimg.com",
            "gstatic.com",
        }
    ),
    frozenset(
        {
            "microsoft.com",
            "outlook.com",
            "live.com",
            "office.com",
            "office365.com",
            "microsoftonline.com",
            "msn.com",
        }
    ),
    frozenset({"apple.com", "icloud.com", "me.com", "mzstatic.com", "cdn-apple.com"}),
    frozenset({"amazon.com", "amazonaws.com", "ssl-images-amazon.com", "media-amazon.com"}),
    frozenset({"paypal.com", "paypalobjects.com"}),
    frozenset({"linkedin.com", "licdn.com"}),
    frozenset({"atlassian.com", "atlassian.net", "bitbucket.org", "jira.com", "trello.com"}),
)

# Header tells that drive the brand-phishing path (before FP clearance).
_BRAND_TELLS = frozenset(
    {
        "display_name_domain_mismatch",
        "cta_off_domain",
        "auth_pass_does_not_validate_display_brand",
    }
)


@dataclass(frozen=True)
class Analysis:
    """Deterministic assessment of a single message."""

    subject: str
    from_addr: str
    to_addr: str
    is_self_addressed: bool
    spf: str | None
    dkim: str | None
    dmarc: str | None
    auth_all_failing: bool
    bitcoin_addresses: tuple[str, ...]
    urls: tuple[str, ...]
    public_ips: tuple[str, ...]
    matched_phrases: tuple[str, ...]
    irregularities: tuple[str, ...]
    disambiguation: tuple[str, ...]
    verdict: str
    confidence: float

    @property
    def is_sextortion(self) -> bool:
        return self.verdict == "sextortion"

    @property
    def is_phishing(self) -> bool:
        return self.verdict == "phishing"

    @property
    def is_scam(self) -> bool:
        return self.verdict in {"sextortion", "phishing"}


def _addr_domain(addr: str) -> str:
    return addr.rpartition("@")[-1].lower().strip()


def _from_display(parsed: ParsedEmail) -> str:
    raw = parsed.headers.get("From") or parsed.headers.get("from") or ""
    m = _FROM_DISPLAY_RE.match(raw.strip())
    return m.group(1).strip() if m else ""


def _header_addr_domain(parsed: ParsedEmail, *names: str) -> str:
    for name in names:
        raw = parsed.headers.get(name) or parsed.headers.get(name.lower()) or ""
        if not raw:
            continue
        m = _ADDR_RE.search(raw)
        candidate = (m.group(1) if m else raw).strip().lower()
        if "@" in candidate:
            return _addr_domain(candidate)
    return ""


def _msgid_host(message_id: str) -> str:
    m = _MSGID_HOST_RE.search(message_id.strip())
    return m.group(1).lower().rstrip(".") if m else ""


def _registrable(host: str) -> str:
    """Best-effort eTLD+1: last two labels (enough for .com/.net/.site phishing)."""
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _org_family(domain: str) -> frozenset[str] | None:
    reg = _registrable(domain)
    for family in _ORG_FAMILIES:
        if reg in family:
            return family
    return None


def _auth_passes(parsed: ParsedEmail) -> bool:
    return any(
        (v or "").lower() == "pass" for v in (parsed.auth.spf, parsed.auth.dkim, parsed.auth.dmarc)
    )


def _identity_haystack(from_addr: str) -> str:
    local, _, domain = from_addr.partition("@")
    return re.sub(r"[^a-z0-9]", "", (local + domain).lower())


def _display_name_domain_mismatch(display: str, from_addr: str) -> bool:
    """True when display-name brand tokens do not appear in From local/domain.

    Catches ``SOFINCO <sofin-support@girlpowertalk.com>`` while allowing
    ``GitHub <noreply@github.com>`` (token present in the domain).
    """
    tokens = _DISPLAY_TOKEN_RE.findall(display)
    if not tokens:
        return False
    haystack = _identity_haystack(from_addr)
    if not haystack:
        return False
    return all(t.lower() not in haystack for t in tokens)


def _cta_hosts(urls: tuple[str, ...]) -> tuple[str, ...]:
    hosts: list[str] = []
    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host and host not in hosts:
            hosts.append(host)
    return tuple(hosts)


def _cta_off_domain(urls: tuple[str, ...], from_domain: str) -> bool:
    if not from_domain or not urls:
        return False
    from_reg = _registrable(from_domain)
    return any(_registrable(host) != from_reg for host in _cta_hosts(urls))


def _cta_in_org_family(urls: tuple[str, ...], from_domain: str) -> bool:
    """True when every CTA host is in From's org family (or exact registrable)."""
    hosts = _cta_hosts(urls)
    if not hosts or not from_domain:
        return False
    family = _org_family(from_domain)
    from_reg = _registrable(from_domain)
    allowed = family if family is not None else frozenset({from_reg})
    return all(_registrable(h) in allowed for h in hosts)


def header_irregularities(parsed: ParsedEmail) -> tuple[str, ...]:
    """Deterministic header tells — no body keywords, no network."""
    found: list[str] = []
    from_domain = _addr_domain(parsed.from_addr)
    display = _from_display(parsed)

    if parsed.is_self_addressed:
        found.append("self_addressed")

    if display and from_domain and _display_name_domain_mismatch(display, parsed.from_addr):
        found.append("display_name_domain_mismatch")

    msgid = parsed.message_id.lower()
    msgid_host = _msgid_host(parsed.message_id)
    if any(marker in msgid for marker in _INFRA_MSGID_MARKERS):
        found.append("synthetic_or_infra_message_id")
    elif (
        msgid_host
        and from_domain
        and _registrable(msgid_host) != _registrable(from_domain)
        and "google.com" not in msgid_host
        and "outlook.com" not in msgid_host
        and "microsoft.com" not in msgid_host
    ):
        # Free ESP Message-IDs often use google/outlook; flag other mismatches.
        found.append("message_id_domain_mismatch")

    rp_domain = _header_addr_domain(parsed, "Return-Path", "Return-path")
    if rp_domain and from_domain and _registrable(rp_domain) != _registrable(from_domain):
        found.append("return_path_domain_mismatch")

    reply_domain = _header_addr_domain(parsed, "Reply-To", "Reply-to")
    if reply_domain and from_domain and _registrable(reply_domain) != _registrable(from_domain):
        found.append("reply_to_domain_mismatch")

    if _cta_off_domain(parsed.indicators.urls, from_domain):
        found.append("cta_off_domain")

    # Passing auth + impersonation cues: SPF pass only authenticates the *domain*.
    if (
        not parsed.auth.all_failing
        and parsed.auth.spf == "pass"
        and "display_name_domain_mismatch" in found
    ):
        found.append("auth_pass_does_not_validate_display_brand")

    return tuple(found)


def disambiguate_false_positives(
    parsed: ParsedEmail,
    irregularities: tuple[str, ...],
) -> tuple[str, ...]:
    """Explain header irregularities that are normal for trusted platforms.

    Returns clearance reason codes. Does **not** clear sextortion (BTC + phrases);
    only softens brand-phishing scoring.
    """
    if not irregularities:
        return ()

    reasons: list[str] = []
    from_domain = _addr_domain(parsed.from_addr)
    from_reg = _registrable(from_domain) if from_domain else ""
    trusted = from_reg in _TRUSTED_NOTIFIER_REGISTRABLES and _auth_passes(parsed)

    if trusted:
        reasons.append("trusted_from_domain_auth_pass")

    if (
        trusted
        and "display_name_domain_mismatch" in irregularities
        and not parsed.is_self_addressed
    ):
        # GitHub/Dependabot/PR authors: person display on notifications@github.com.
        reasons.append("person_display_on_trusted_notifier")

    if "cta_off_domain" in irregularities and _cta_in_org_family(
        parsed.indicators.urls, from_domain
    ):
        reasons.append("cta_same_org_family")

    # Authenticated trusted From + sibling CDN links fully explain the brand path.
    if (
        trusted
        and "auth_pass_does_not_validate_display_brand" in irregularities
        and "person_display_on_trusted_notifier" in reasons
    ):
        reasons.append("auth_pass_expected_for_notifier_display")

    return tuple(reasons)


def effective_irregularities(
    irregularities: tuple[str, ...],
    disambiguation: tuple[str, ...],
) -> tuple[str, ...]:
    """Drop header tells that disambiguation has explained away."""
    cleared: set[str] = set()
    if "person_display_on_trusted_notifier" in disambiguation:
        cleared.add("display_name_domain_mismatch")
    if "auth_pass_expected_for_notifier_display" in disambiguation:
        cleared.add("auth_pass_does_not_validate_display_brand")
    if "cta_same_org_family" in disambiguation:
        cleared.add("cta_off_domain")
    return tuple(i for i in irregularities if i not in cleared)


def analyze(parsed: ParsedEmail) -> Analysis:
    """Score a parsed message deterministically from headers + indicators."""
    body_l = parsed.body.lower()
    matched = tuple(p for p in _SEXTORTION_PHRASES if p in body_l)
    has_btc = bool(parsed.indicators.bitcoin_addresses)
    irregularities = header_irregularities(parsed)
    disambiguation = disambiguate_false_positives(parsed, irregularities)
    effective = effective_irregularities(irregularities, disambiguation)
    irr_n = len(effective)

    # Sextortion signals (crypto + phrasing remain decisive for that family).
    sex_signals = 0
    sex_signals += 1 if parsed.is_self_addressed else 0
    sex_signals += 1 if parsed.auth.all_failing else 0
    sex_signals += 1 if has_btc else 0
    sex_signals += 1 if len(matched) >= 2 else 0

    has_brand_tell = bool(_BRAND_TELLS.intersection(effective))

    if has_btc and len(matched) >= 2:
        verdict = "sextortion"
        confidence = min(1.0, 0.6 + 0.1 * sex_signals)
    elif has_brand_tell and irr_n >= 2:
        # Sofinco-class: alien display brand + at least one other header tell.
        verdict = "phishing"
        confidence = min(0.95, 0.5 + 0.08 * irr_n)
    elif len(matched) >= 1 or has_btc or irr_n >= 2:
        verdict = "suspicious"
        confidence = 0.3 + 0.08 * max(sex_signals, irr_n)
    else:
        verdict = "unknown"
        confidence = 0.1

    return Analysis(
        subject=parsed.subject,
        from_addr=parsed.from_addr,
        to_addr=parsed.to_addr,
        is_self_addressed=parsed.is_self_addressed,
        spf=parsed.auth.spf,
        dkim=parsed.auth.dkim,
        dmarc=parsed.auth.dmarc,
        auth_all_failing=parsed.auth.all_failing,
        bitcoin_addresses=parsed.indicators.bitcoin_addresses,
        urls=parsed.indicators.urls,
        public_ips=parsed.indicators.public_ips,
        matched_phrases=matched,
        irregularities=irregularities,
        disambiguation=disambiguation,
        verdict=verdict,
        confidence=round(min(1.0, confidence), 2),
    )


_SUMMARY_SYSTEM = (
    "You are a defensive email-abuse analyst. Summarize the scam email for a victim "
    "in 3 short sentences: what it claims, why it is a bluff, and what to do "
    "(do not pay; do not click; report it). Be calm and factual."
)


def summarize(
    parsed: ParsedEmail,
    router: ProviderRouter,
    *,
    escalate: bool = False,
) -> str:
    """Draft a human-readable summary via the LLM router (local by default).

    When ``escalate=True`` the router uses the guarded cloud provider; the prompt is
    redacted and routed through ShieldFlow by that provider.
    """
    # Collapse whitespace; the model only needs the gist, not the full raw body.
    body = re.sub(r"\s+", " ", parsed.body).strip()
    prompt = f"Subject: {parsed.subject}\n\nBody: {body}"
    return router.complete(prompt, system=_SUMMARY_SYSTEM, escalate=escalate)
