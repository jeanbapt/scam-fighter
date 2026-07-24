"""ScamFighter core: typed models and the governance abstraction.

Governance is a pluggable boundary. Phase 1 ships :class:`LocalGovernance`;
SGRS (or any other engine) can be added later as an adapter behind
:class:`Governance` without touching agents or MCP servers.
"""

from scamfighter_core.dnsbl import DnsblHit, DnsblResult, enrich_dnsbl
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
from scamfighter_core.filing import (
    ApprovalGate,
    PackSnapshot,
    confirm_action,
    draft_abuse_mailto,
    form_fill_plan,
    load_pack,
    request_spamhaus_submit,
    submit_spamhaus_email,
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
from scamfighter_core.provenance import (
    BtcProvenance,
    DomainProvenance,
    IpProvenance,
    ProvenanceReport,
    format_provenance_markdown,
)
from scamfighter_core.provenance import (
    enrich as enrich_provenance,
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
    "ApprovalGate",
    "AuditEvent",
    "AuditTampered",
    "AuthResults",
    "BtcProvenance",
    "CallableSemanticGuard",
    "CaseState",
    "CompositeEgressGuard",
    "DeterministicRedactor",
    "DnsblHit",
    "DnsblResult",
    "DomainProvenance",
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
    "IpProvenance",
    "LLMProvider",
    "LocalGovernance",
    "MacMailSource",
    "MailSource",
    "MessageTooLarge",
    "OllamaLocalProvider",
    "OpenAICompatibleProvider",
    "PackSnapshot",
    "ParsedEmail",
    "ProvenanceReport",
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
    "confirm_action",
    "defang",
    "default_mac_mail_root",
    "draft_abuse_mailto",
    "egress_audit_record",
    "enrich_dnsbl",
    "enrich_provenance",
    "form_fill_plan",
    "format_provenance_markdown",
    "guard_cloud_egress",
    "html_to_text",
    "httpx_transport",
    "is_active",
    "load_config",
    "load_pack",
    "parse_eml",
    "parse_eml_bytes",
    "parse_emlx",
    "read_message_file",
    "request_spamhaus_submit",
    "requests_transport",
    "submit_spamhaus_email",
    "summarize",
]
