"""ScamFighter core: typed models and the governance abstraction.

Governance is a pluggable boundary. Phase 1 ships :class:`LocalGovernance`;
SGRS (or any other engine) can be added later as an adapter behind
:class:`Governance` without touching agents or MCP servers.
"""

from scamfighter_core.egress_guard import (
    CompositeEgressGuard,
    DeterministicRedactor,
    EgressBlocked,
    EgressGuard,
    GuardVerdict,
    ShieldFlowClient,
    ShieldFlowGuard,
    ShieldFlowResponse,
    guard_cloud_egress,
)
from scamfighter_core.email_ingest import (
    AuthResults,
    Indicators,
    ParsedEmail,
    defang,
    parse_eml,
)
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
    "AuthResults",
    "CaseState",
    "CompositeEgressGuard",
    "DeterministicRedactor",
    "EgressBlocked",
    "EgressGuard",
    "Governance",
    "GovernanceError",
    "GuardVerdict",
    "Indicators",
    "LocalGovernance",
    "ParsedEmail",
    "ShieldFlowClient",
    "ShieldFlowGuard",
    "ShieldFlowResponse",
    "Transition",
    "UnauthorizedTransition",
    "defang",
    "guard_cloud_egress",
    "parse_eml",
]
