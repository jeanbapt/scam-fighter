"""End-to-end analysis: source -> parse -> deterministic verdict -> optional summary.

The classification of this scam family is deterministic on purpose (see the models
section of ``docs/IMPLEMENTATION_PLAN.md``): self-addressed spoof + failed
authentication + crypto demand is a sextortion signature that needs no LLM. The
LLM is optional and only used to draft a human-readable summary, gated by the
egress guard when it runs in the cloud.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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
    verdict: str
    confidence: float

    @property
    def is_sextortion(self) -> bool:
        return self.verdict == "sextortion"


def analyze(parsed: ParsedEmail) -> Analysis:
    """Score a parsed message deterministically."""
    body_l = parsed.body.lower()
    matched = tuple(p for p in _SEXTORTION_PHRASES if p in body_l)
    has_btc = bool(parsed.indicators.bitcoin_addresses)

    # Signals: self-addressed spoof, failed auth, crypto demand, scam phrasing.
    signals = 0
    signals += 1 if parsed.is_self_addressed else 0
    signals += 1 if parsed.auth.all_failing else 0
    signals += 1 if has_btc else 0
    signals += 1 if len(matched) >= 2 else 0

    if has_btc and len(matched) >= 2:
        verdict = "sextortion"
        confidence = min(1.0, 0.6 + 0.1 * signals)
    elif len(matched) >= 1 or has_btc:
        verdict = "suspicious"
        confidence = 0.3 + 0.1 * signals
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
        verdict=verdict,
        confidence=round(confidence, 2),
    )


_SUMMARY_SYSTEM = (
    "You are a defensive email-abuse analyst. Summarize the scam email for a victim "
    "in 3 short sentences: what it claims, why it is a bluff, and what to do "
    "(do not pay; report it). Be calm and factual."
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
