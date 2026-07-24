"""ScamFighter core: typed models and the governance abstraction.

Governance is a pluggable boundary. Phase 1 ships :class:`LocalGovernance`;
SGRS (or any other engine) can be added later as an adapter behind
:class:`Governance` without touching agents or MCP servers.
"""

from scamfighter_core.egress_guard import (
    CallableSemanticGuard,
    CompositeEgressGuard,
    DeterministicRedactor,
    EgressBlocked,
    EgressGuard,
    GuardVerdict,
    SemanticGuardClient,
    SemanticGuardResponse,
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
from scamfighter_core.shieldflow import (
    ShieldFlowConfig,
    ShieldFlowGuard,
    httpx_transport,
    is_active,
    load_config,
    requests_transport,
)

__all__ = [
    "ApprovalDecision",
    "AuditEvent",
    "AuthResults",
    "CallableSemanticGuard",
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
    "SemanticGuardClient",
    "SemanticGuardResponse",
    "ShieldFlowConfig",
    "ShieldFlowGuard",
    "Transition",
    "UnauthorizedTransition",
    "defang",
    "guard_cloud_egress",
    "httpx_transport",
    "is_active",
    "load_config",
    "parse_eml",
    "requests_transport",
]
