# ScamFighter Filing MCP

Observe-first MCP for evidence packs: DNSBL lookup, abuse mailto drafts,
Spamhaus Submission Portal (confirm-gated), and form field maps for Playwright.

**How to drive this with an LLM (prompts, gates, Cursor / Claude setup):**  
→ **[docs/MCP_FILING.md](../../docs/MCP_FILING.md)**

## Tools

| Tool | Network | Notes |
|------|---------|-------|
| `load_evidence_pack` | no | Path or case_id under `SCAMFIGHTER_PACKS` |
| `enrich_ip_dnsbl` | DNS only | Spamhaus ZEN + Barracuda |
| `draft_mailto` | no | Writes `draft_mailto_*.eml` in the pack |
| `request_spamhaus_raw_email` | no | Returns approval token |
| `confirm_filing_action` | no | Requires `confirmation="I_CONFIRM_SUBMIT"` |
| `submit_spamhaus_raw_email` | HTTPS if live | Needs confirm + `dry_run=false` + `SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1` |
| `get_form_fill_plan` | no | `ovh_abuse` / `pharos` / `thesee` / `signal_spam` |
| `filing_confirm_phrase` | no | Returns the exact confirm string |

**Never auto-submits browser forms.** Pair form plans with Playwright MCP; THESEE
FranceConnect stays human.

## Cursor / Claude Desktop config

```json
{
  "mcpServers": {
    "scamfighter-filing": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp",
        "python",
        "-m",
        "scamfighter_filing_mcp"
      ],
      "cwd": "/ABSOLUTE/PATH/TO/scamfighter/mcp_servers/filing",
      "env": {
        "PYTHONPATH": "/ABSOLUTE/PATH/TO/scamfighter/packages/scamfighter_core",
        "SCAMFIGHTER_PACKS": "/ABSOLUTE/PATH/TO/home/ScamFighter/packs",
        "SPAMHAUS_API_TOKEN": "",
        "SCAMFIGHTER_ALLOW_LIVE_SUBMIT": ""
      }
    }
  }
}
```

Create a Spamhaus token at https://auth.spamhaus.org/account (API Key Creation).

## Legal posture

Defensive intermediary only. See `docs/FILING.md` and `docs/LEGAL.md`. Do not
browse live scam URLs; attach local `message.eml` only.
