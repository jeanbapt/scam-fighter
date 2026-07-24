"""Cloud egress guard: the chokepoint before any content leaves the device.

Cloud LLM escalation is opt-in and dangerous for two reasons:

1. **Privacy** — scam mail contains PII (victim + third parties). Sending raw text
   to a cloud model would be an unlawful/undesirable data offload
   (see ``docs/LEGAL.md``).
2. **Prompt injection** — the email body is attacker-controlled text; feeding it to
   a cloud model is an injection vector (see ``docs/THREAT_MODEL.md``).

So every string bound for the cloud passes through an :class:`EgressGuard` that
redacts PII and detects injection, and the pipeline **fails closed**: if the guard
cannot vouch for the text, it is not sent.

Layers:

* :class:`DeterministicRedactor` — always available, no model. Reliably masks
  structured PII (emails, IPs, crypto addresses, URLs, phone-like numbers). It does
  NOT understand free-text PII (names, addresses) and does NOT detect injection.
* :class:`CallableSemanticGuard` — generic in-process semantic guard adapter for a
  model that redacts free-text PII and/or detects injection (e.g. Microsoft
  Presidio or OpenAI Privacy Filter). Inject a client callable; unconfigured it
  fails closed.
* :class:`CompositeEgressGuard` — chains guards; in ``strict`` mode it refuses to
  clear text unless a semantic guard has vetted it.

The primary semantic guard in this project is LiquidAI ShieldFlow, which runs as a
local egress proxy rather than an in-process call — see
:mod:`scamfighter_core.shieldflow`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Protocol, runtime_checkable

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]{1,2048}", re.IGNORECASE)
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
# Bounded phone-like numbers; avoid nested quantifiers that invite ReDoS.
_PHONE_RE = re.compile(r"(?<!\w)\+\d{1,3}(?:[\s().-]?\d){6,14}(?!\w)")

# (label, pattern) applied in order; URLs before emails/IPs so nested matches don't
# leave fragments behind.
_REDACTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("URL", _URL_RE),
    ("EMAIL", _EMAIL_RE),
    ("BTC", _BTC_RE),
    ("IP", _IPV4_RE),
    ("PHONE", _PHONE_RE),
)


class EgressBlocked(Exception):
    """Raised when guarded text may not leave the device."""


@dataclass(frozen=True)
class GuardVerdict:
    """Result of inspecting a piece of text bound for the cloud."""

    allowed: bool
    text: str
    findings: tuple[str, ...] = ()
    injection_detected: bool = False
    semantic_pii_checked: bool = False
    reason: str = ""

    def merge(self, other: GuardVerdict) -> GuardVerdict:
        """Combine two verdicts; blocking wins, redactions accumulate."""
        return GuardVerdict(
            allowed=self.allowed and other.allowed,
            text=other.text,
            findings=tuple(dict.fromkeys((*self.findings, *other.findings))),
            injection_detected=self.injection_detected or other.injection_detected,
            semantic_pii_checked=self.semantic_pii_checked or other.semantic_pii_checked,
            reason="; ".join(r for r in (self.reason, other.reason) if r),
        )


@runtime_checkable
class EgressGuard(Protocol):
    """Boundary every cloud-bound string must pass. Implementations are adapters."""

    def inspect(self, text: str) -> GuardVerdict:
        """Return a verdict; must not have network side effects beyond the guard."""
        ...


class DeterministicRedactor:
    """No-model, always-available structured-PII redactor.

    Reliable for what regex can catch; deliberately does not claim to cover
    free-text PII or prompt injection (``semantic_pii_checked`` stays False).
    """

    def inspect(self, text: str) -> GuardVerdict:
        redacted = text
        findings: list[str] = []
        for label, pattern in _REDACTIONS:
            if pattern.search(redacted):
                findings.append(label)
                redacted = pattern.sub(f"[REDACTED_{label}]", redacted)
        return GuardVerdict(
            allowed=True,
            text=redacted,
            findings=tuple(findings),
            injection_detected=False,
            semantic_pii_checked=False,
            reason="deterministic redaction only" if findings else "",
        )


@dataclass(frozen=True)
class SemanticGuardResponse:
    """Normalized response from an in-process semantic guard model.

    Adapt a model's actual output (Presidio, OpenAI Privacy Filter, ...) into this
    shape when wiring it.
    """

    redacted_text: str
    pii_labels: tuple[str, ...] = ()
    injection_detected: bool = False


# Operator-supplied callable that runs a semantic guard on-device.
SemanticGuardClient = Callable[[str], SemanticGuardResponse]


class CallableSemanticGuard:
    """Generic adapter for an in-process semantic guard model.

    Use for free-text PII (names, addresses) and/or injection detection when the
    guard is a Python-callable model. With no client it **fails closed** (blocks),
    so escalation never silently downgrades to weaker protection.

    (LiquidAI ShieldFlow is not wired here — it runs as a proxy; see
    :mod:`scamfighter_core.shieldflow`.)
    """

    def __init__(self, client: SemanticGuardClient | None = None) -> None:
        self._client = client

    def inspect(self, text: str) -> GuardVerdict:
        if self._client is None:
            return GuardVerdict(
                allowed=False,
                text=text,
                reason="semantic guard not configured (fail closed)",
            )
        resp = self._client(text)
        return GuardVerdict(
            allowed=not resp.injection_detected,
            text=resp.redacted_text,
            findings=resp.pii_labels,
            injection_detected=resp.injection_detected,
            semantic_pii_checked=True,
            reason="prompt injection detected" if resp.injection_detected else "",
        )


class CompositeEgressGuard:
    """Run guards in sequence, threading redacted text through each.

    In ``strict`` mode (default), text is only cleared if a semantic guard (e.g.
    ShieldFlow) vetted it — deterministic redaction alone is never enough to send
    free-text to the cloud.
    """

    def __init__(self, guards: Sequence[EgressGuard], *, strict: bool = True) -> None:
        if not guards:
            raise ValueError("CompositeEgressGuard requires at least one guard")
        self._guards = tuple(guards)
        self._strict = strict

    def inspect(self, text: str) -> GuardVerdict:
        verdict = GuardVerdict(allowed=True, text=text, semantic_pii_checked=False)
        for guard in self._guards:
            verdict = verdict.merge(guard.inspect(verdict.text))
        if self._strict and verdict.allowed and not verdict.semantic_pii_checked:
            verdict = replace(
                verdict,
                allowed=False,
                reason=(verdict.reason + "; " if verdict.reason else "")
                + "no semantic PII guard vetted the text (strict mode)",
            )
        return verdict


def guard_cloud_egress(text: str, guard: EgressGuard) -> str:
    """Return redacted text safe to send to the cloud, or raise :class:`EgressBlocked`.

    This is the single call sites should use before any cloud LLM request.
    """
    verdict = guard.inspect(text)
    if not verdict.allowed:
        raise EgressBlocked(verdict.reason or "egress guard blocked the request")
    return verdict.text
