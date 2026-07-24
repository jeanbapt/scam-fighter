"""ScamFighter core: typed models and the governance abstraction.

Governance is a pluggable boundary. Phase 1 ships :class:`LocalGovernance`;
SGRS (or any other engine) can be added later as an adapter behind
:class:`Governance` without touching agents or MCP servers.
"""

from scamfighter_core.governance import (
    ApprovalDecision,
    AuditEvent,
    CaseState,
    Governance,
    GovernanceError,
    LocalGovernance,
    Transition,
    UnauthorizedTransition,
)

__all__ = [
    "ApprovalDecision",
    "AuditEvent",
    "CaseState",
    "Governance",
    "GovernanceError",
    "LocalGovernance",
    "Transition",
    "UnauthorizedTransition",
]
