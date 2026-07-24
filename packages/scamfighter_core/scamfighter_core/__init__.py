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
    egress_audit_record,
    guard_cloud_egress,
)
from scamfighter_core.email_ingest import (
    AuthResults,
    Indicators,
    ParsedEmail,
    defang,
    html_to_text,
    parse_eml,
    parse_eml_bytes,
)
from scamfighter_core.governance import (
    ApprovalDecision,
    AuditEvent,
    AuditTampered,
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
    MAX_MESSAGE_BYTES,
    FolderSource,
    ImapSource,
    MacMailSource,
    MailSource,
    MessageTooLarge,
    default_mac_mail_root,
    parse_emlx,
    read_message_file,
)
from scamfighter_core.pack import EvidencePack, build_pack
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
from scamfighter_core.vault import (
    EvidenceVault,
    VaultConflict,
    VaultError,
    VaultObject,
)

__all__ = [
    "MAX_MESSAGE_BYTES",
    "Analysis",
    "ApprovalDecision",
    "AuditEvent",
    "AuditTampered",
    "AuthResults",
    "CallableSemanticGuard",
    "CaseState",
    "CompositeEgressGuard",
    "DeterministicRedactor",
    "EgressBlocked",
    "EgressGuard",
    "EvidencePack",
    "EvidenceVault",
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
    "MessageTooLarge",
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
    "VaultConflict",
    "VaultError",
    "VaultObject",
    "analyze",
    "build_pack",
    "defang",
    "default_mac_mail_root",
    "egress_audit_record",
    "guard_cloud_egress",
    "html_to_text",
    "httpx_transport",
    "is_active",
    "load_config",
    "parse_eml",
    "parse_eml_bytes",
    "parse_emlx",
    "read_message_file",
    "requests_transport",
    "summarize",
]
