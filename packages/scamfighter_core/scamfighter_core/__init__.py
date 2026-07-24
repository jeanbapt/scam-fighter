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
from scamfighter_core.llm import (
    LLMProvider,
    OllamaLocalProvider,
    OpenAICompatibleProvider,
    ProviderRouter,
)
from scamfighter_core.mail_source import (
    FolderSource,
    ImapSource,
    MacMailSource,
    MailSource,
    default_mac_mail_root,
    parse_emlx,
)
from scamfighter_core.pipeline import (
    Analysis,
    analyze,
    summarize,
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
    "Analysis",
    "ApprovalDecision",
    "AuditEvent",
    "AuthResults",
    "CallableSemanticGuard",
    "CaseState",
    "CompositeEgressGuard",
    "DeterministicRedactor",
    "EgressBlocked",
    "EgressGuard",
    "FolderSource",
    "Governance",
    "GovernanceError",
    "GuardVerdict",
    "ImapSource",
    "Indicators",
    "LLMProvider",
    "LocalGovernance",
    "MacMailSource",
    "MailSource",
    "OllamaLocalProvider",
    "OpenAICompatibleProvider",
    "ParsedEmail",
    "ProviderRouter",
    "SemanticGuardClient",
    "SemanticGuardResponse",
    "ShieldFlowConfig",
    "ShieldFlowGuard",
    "Transition",
    "UnauthorizedTransition",
    "analyze",
    "defang",
    "default_mac_mail_root",
    "guard_cloud_egress",
    "httpx_transport",
    "is_active",
    "load_config",
    "parse_eml",
    "parse_emlx",
    "requests_transport",
    "summarize",
]
