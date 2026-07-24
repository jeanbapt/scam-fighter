"""Governance boundary for ScamFighter.

Every side-effecting action (mutating mail, filing an abuse report, notifying a
registrar) MUST pass through a :class:`Governance` implementation. This gives us
three guarantees regardless of the backend:

1. A validated state machine (only allowed transitions happen).
2. An approval gate before any side effect.
3. A tamper-evident, append-only audit trail.

Phase 1 ships :class:`LocalGovernance` (stdlib only, no external dependency).
An ``SgrsGovernance`` adapter can implement the same :class:`Governance`
Protocol later without changing agents or MCP servers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Protocol, runtime_checkable


class CaseState(str, Enum):
    """Lifecycle of a single abuse case."""

    INGESTED = "ingested"
    ANALYZED = "analyzed"
    EVIDENCED = "evidenced"
    PLANNED = "planned"
    APPROVED = "approved"
    EXECUTED = "executed"
    CLOSED = "closed"


# Allowed forward transitions. Anything not listed here is rejected.
_ALLOWED: dict[CaseState, frozenset[CaseState]] = {
    CaseState.INGESTED: frozenset({CaseState.ANALYZED, CaseState.CLOSED}),
    CaseState.ANALYZED: frozenset({CaseState.EVIDENCED, CaseState.CLOSED}),
    CaseState.EVIDENCED: frozenset({CaseState.PLANNED, CaseState.CLOSED}),
    CaseState.PLANNED: frozenset({CaseState.APPROVED, CaseState.CLOSED}),
    CaseState.APPROVED: frozenset({CaseState.EXECUTED, CaseState.CLOSED}),
    CaseState.EXECUTED: frozenset({CaseState.CLOSED}),
    CaseState.CLOSED: frozenset(),
}

# States whose entry represents a real side effect and therefore requires an
# approval decision to already be on record.
_REQUIRES_APPROVAL: frozenset[CaseState] = frozenset({CaseState.EXECUTED})


class GovernanceError(Exception):
    """Base class for governance failures."""


class UnauthorizedTransition(GovernanceError):
    """Raised when a state transition is not permitted."""


@dataclass(frozen=True)
class Transition:
    """A requested move from one case state to another."""

    case_id: str
    frm: CaseState
    to: CaseState
    actor: str
    reason: str = ""


@dataclass(frozen=True)
class ApprovalDecision:
    """A human or policy approval for a proposed action."""

    case_id: str
    approved: bool
    approver: str
    note: str = ""
    at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class AuditEvent:
    """One append-only, hash-chained audit record."""

    case_id: str
    kind: str
    payload: dict[str, str]
    at: datetime
    prev_hash: str
    this_hash: str

    @staticmethod
    def compute_hash(
        case_id: str, kind: str, payload: dict[str, str], at: datetime, prev_hash: str
    ) -> str:
        body = json.dumps(
            {
                "case_id": case_id,
                "kind": kind,
                "payload": payload,
                "at": at.isoformat(),
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


@runtime_checkable
class Governance(Protocol):
    """The boundary every action-taking component depends on.

    Implementations: :class:`LocalGovernance` (Phase 1) and, later, an SGRS
    adapter. Agents and MCP servers depend on this Protocol, never on a concrete
    engine.
    """

    def propose_transition(self, transition: Transition) -> None:
        """Validate and record a state transition, or raise ``GovernanceError``."""
        ...

    def require_approval(self, case_id: str) -> ApprovalDecision:
        """Return the recorded approval for a case, or raise if none/denied."""
        ...

    def record_approval(self, decision: ApprovalDecision) -> None:
        """Persist an approval decision for later gating."""
        ...

    def audit_log(self, case_id: str) -> list[AuditEvent]:
        """Return the append-only audit trail for a case."""
        ...


class LocalGovernance:
    """Dependency-free Phase 1 governance backend.

    Keeps an in-memory, hash-chained audit log and a validated state machine.
    Swap for a durable backend (SQLite) or an SGRS adapter without changing
    callers.
    """

    def __init__(self) -> None:
        self._state: dict[str, CaseState] = {}
        self._approvals: dict[str, ApprovalDecision] = {}
        self._audit: dict[str, list[AuditEvent]] = {}

    def _append_audit(self, case_id: str, kind: str, payload: dict[str, str]) -> None:
        chain = self._audit.setdefault(case_id, [])
        prev_hash = chain[-1].this_hash if chain else "0" * 64
        at = datetime.now(UTC)
        this_hash = AuditEvent.compute_hash(case_id, kind, payload, at, prev_hash)
        chain.append(
            AuditEvent(
                case_id=case_id,
                kind=kind,
                payload=payload,
                at=at,
                prev_hash=prev_hash,
                this_hash=this_hash,
            )
        )

    def propose_transition(self, transition: Transition) -> None:
        current = self._state.get(transition.case_id, CaseState.INGESTED)
        if transition.frm != current:
            raise UnauthorizedTransition(
                f"case {transition.case_id} is in {current}, not {transition.frm}"
            )
        if transition.to not in _ALLOWED[transition.frm]:
            raise UnauthorizedTransition(
                f"transition {transition.frm} -> {transition.to} is not allowed"
            )
        if transition.to in _REQUIRES_APPROVAL:
            decision = self._approvals.get(transition.case_id)
            if decision is None or not decision.approved:
                raise UnauthorizedTransition(
                    f"transition to {transition.to} requires a recorded approval"
                )
        self._state[transition.case_id] = transition.to
        self._append_audit(
            transition.case_id,
            "transition",
            {"from": transition.frm.value, "to": transition.to.value, "actor": transition.actor},
        )

    def record_approval(self, decision: ApprovalDecision) -> None:
        self._approvals[decision.case_id] = decision
        self._append_audit(
            decision.case_id,
            "approval",
            {"approved": str(decision.approved), "approver": decision.approver},
        )

    def require_approval(self, case_id: str) -> ApprovalDecision:
        decision = self._approvals.get(case_id)
        if decision is None:
            raise GovernanceError(f"no approval recorded for case {case_id}")
        if not decision.approved:
            raise UnauthorizedTransition(f"case {case_id} was denied by {decision.approver}")
        return decision

    def audit_log(self, case_id: str) -> list[AuditEvent]:
        return list(self._audit.get(case_id, []))

    def current_state(self, case_id: str) -> CaseState:
        return self._state.get(case_id, CaseState.INGESTED)
