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
from pathlib import Path
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


class AuditTampered(GovernanceError):
    """Raised when a persisted audit chain fails verification."""


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

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "payload": self.payload,
            "at": self.at.isoformat(),
            "prev_hash": self.prev_hash,
            "this_hash": self.this_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AuditEvent:
        payload = data["payload"]
        if not isinstance(payload, dict):
            raise AuditTampered("audit payload must be an object")
        return cls(
            case_id=str(data["case_id"]),
            kind=str(data["kind"]),
            payload={str(k): str(v) for k, v in payload.items()},
            at=datetime.fromisoformat(str(data["at"])),
            prev_hash=str(data["prev_hash"]),
            this_hash=str(data["this_hash"]),
        )


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

    Keeps a hash-chained audit log and a validated state machine. Pass
    ``audit_path`` to persist events as append-only JSONL; on init the file is
    loaded and :meth:`verify_chain` must succeed (fail closed on tamper).
    """

    def __init__(self, audit_path: Path | None = None) -> None:
        self._state: dict[str, CaseState] = {}
        self._approvals: dict[str, ApprovalDecision] = {}
        self._audit: dict[str, list[AuditEvent]] = {}
        self._audit_path = audit_path
        if audit_path is not None:
            self._load_audit(audit_path)

    def _append_audit(self, case_id: str, kind: str, payload: dict[str, str]) -> None:
        chain = self._audit.setdefault(case_id, [])
        prev_hash = chain[-1].this_hash if chain else "0" * 64
        at = datetime.now(UTC)
        this_hash = AuditEvent.compute_hash(case_id, kind, payload, at, prev_hash)
        event = AuditEvent(
            case_id=case_id,
            kind=kind,
            payload=payload,
            at=at,
            prev_hash=prev_hash,
            this_hash=this_hash,
        )
        chain.append(event)
        if self._audit_path is not None:
            self._persist_event(event)

    def _persist_event(self, event: AuditEvent) -> None:
        assert self._audit_path is not None
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")

    def _load_audit(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AuditTampered(f"cannot read audit log: {exc}") from exc
        for line_no, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise AuditTampered(f"line {line_no}: expected object")
                event = AuditEvent.from_dict(data)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise AuditTampered(f"line {line_no}: corrupt audit record ({exc})") from exc
            self._audit.setdefault(event.case_id, []).append(event)
            self._replay_event(event)
        for case_id in self._audit:
            if not self.verify_chain(case_id):
                raise AuditTampered(f"audit chain failed verification for case {case_id}")

    def _replay_event(self, event: AuditEvent) -> None:
        """Rebuild in-memory state/approvals from a persisted event."""
        if event.kind == "transition":
            to_raw = event.payload.get("to")
            if to_raw:
                try:
                    self._state[event.case_id] = CaseState(to_raw)
                except ValueError:
                    raise AuditTampered(f"unknown state in audit: {to_raw}") from None
        elif event.kind == "approval":
            approved = event.payload.get("approved", "").lower() == "true"
            self._approvals[event.case_id] = ApprovalDecision(
                case_id=event.case_id,
                approved=approved,
                approver=event.payload.get("approver", ""),
                at=event.at,
            )

    def verify_chain(self, case_id: str) -> bool:
        """Recompute the hash chain; return False if any link is broken."""
        chain = self._audit.get(case_id, [])
        expected_prev = "0" * 64
        for event in chain:
            if event.prev_hash != expected_prev:
                return False
            recomputed = AuditEvent.compute_hash(
                event.case_id, event.kind, event.payload, event.at, event.prev_hash
            )
            if recomputed != event.this_hash:
                return False
            expected_prev = event.this_hash
        return True

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
