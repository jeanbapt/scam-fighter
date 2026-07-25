"""ScamFighter filing MCP — pack → DNSBL / mailto / Spamhaus / form plans.

Observe-only by default. Submits require confirm_action + explicit tool call.
Stdio entry: ``python -m scamfighter_filing_mcp`` (needs ``mcp`` package).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Allow running from a repo checkout without installing the package.
_REPO = Path(__file__).resolve().parents[3]
_CORE = _REPO / "packages" / "scamfighter_core"
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from scamfighter_core.dnsbl import enrich_dnsbl  # noqa: E402
from scamfighter_core.filing import (  # noqa: E402
    CONFIRM_PHRASE,
    confirm_action,
    draft_abuse_mailto,
    form_fill_plan,
    load_pack,
    request_spamhaus_submit,
    submit_spamhaus_email,
)


def _tool_result(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def build_mcp_server() -> Any:
    """Create a FastMCP server instance (requires ``mcp``)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "Install the MCP SDK: uv run --with mcp python -m scamfighter_filing_mcp"
        ) from exc

    mcp = FastMCP("scamfighter-filing")

    @mcp.tool()
    def load_evidence_pack(path_or_case_id: str) -> str:
        """Load a pack by case_id or path under SCAMFIGHTER_PACKS only."""
        return _tool_result(load_pack(path_or_case_id).to_dict())

    @mcp.tool()
    def enrich_ip_dnsbl(ip: str) -> str:
        """Query Spamhaus ZEN + Barracuda DNSBLs for an IPv4 address (lookup only)."""
        return _tool_result(enrich_dnsbl(ip))

    @mcp.tool()
    def draft_mailto(path_or_case_id: str, to: str, lang: str = "fr") -> str:
        """Write an RFC822 draft with message.eml attached (does not send)."""
        pack = load_pack(path_or_case_id)
        return _tool_result(draft_abuse_mailto(pack, to=to, lang=lang))

    @mcp.tool()
    def request_spamhaus_raw_email(path_or_case_id: str, reason: str) -> str:
        """Prepare Spamhaus raw-.eml submit and return an approval token (not sent yet)."""
        pack = load_pack(path_or_case_id)
        return _tool_result(request_spamhaus_submit(pack, reason=reason[:255]))

    @mcp.tool()
    def confirm_filing_action(approval_token: str, confirmation: str) -> str:
        """Confirm a pending submit. confirmation must be exactly I_CONFIRM_SUBMIT."""
        return _tool_result(confirm_action(approval_token, confirmation=confirmation))

    @mcp.tool()
    def submit_spamhaus_raw_email(approval_token: str, dry_run: bool = True) -> str:
        """POST to Spamhaus after confirm. Live submit needs SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1."""
        return _tool_result(submit_spamhaus_email(approval_token, dry_run=dry_run))

    @mcp.tool()
    def get_form_fill_plan(channel: str, path_or_case_id: str) -> str:
        """Field map for OVH / Pharos / THESEE / Signal Spam (Playwright assist; no auto-submit)."""
        pack = load_pack(path_or_case_id)
        return _tool_result(form_fill_plan(channel, pack))

    @mcp.tool()
    def filing_confirm_phrase() -> str:
        """Return the exact confirmation phrase humans must type for confirm_filing_action."""
        return _tool_result({"confirmation_phrase": CONFIRM_PHRASE})

    return mcp


def main() -> None:
    server = build_mcp_server()
    server.run(transport="stdio")
