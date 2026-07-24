# ScamFighter Filing MCP

Observe-first MCP for evidence packs: DNSBL lookup, abuse mailto drafts,
Spamhaus Submission Portal (confirm-gated), and form field maps for Playwright.

## Tools

| Tool | Network | Notes |
|------|---------|-------|
| `load_evidence_pack` | no | Path or case_id under `SCAMFIGHTER_PACKS` |
| `enrich_ip_dnsbl` | DNS only | Spamhaus ZEN + Barracuda |
| `draft_mailto` | no | Writes `draft_mailto_*.eml` in the pack |
| `request_spamhaus_raw_email` | no | Returns approval token |
| `confirm_filing_action` | no | Human gate |
| `submit_spamhaus_raw_email` | HTTPS if `dry_run=false` | Needs `SPAMHAUS_API_TOKEN` |
| `get_form_fill_plan` | no | `ovh_abuse` / `pharos` / `thesee` / `signal_spam` |

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
        "SCAMFIGHTER_PACKS": "/Users/YOU/ScamFighter/packs",
        "SPAMHAUS_API_TOKEN": ""
      }
    }
  }
}
```

Create a Spamhaus token at https://auth.spamhaus.org/account (API Key Creation).

## Legal posture

Defensive intermediary only. See `docs/FILING.md` and `docs/LEGAL.md`. Do not
browse live scam URLs; attach local `message.eml` only.
