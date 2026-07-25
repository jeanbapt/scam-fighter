# Using an LLM with the ScamFighter filing MCP

This guide shows how to connect a chat model (Cursor Agent, Claude Desktop,
or any MCP-capable client) to **scamfighter-filing** so the model can prepare
abuse filings from a local evidence pack — without auto-sending mail or browsing
scam URLs.

Legal posture: defensive intermediary only. See [LEGAL.md](LEGAL.md) and
[FILING.md](FILING.md).

## What the LLM is allowed to do

| Allowed | Not allowed |
|---------|-------------|
| Load a pack under `~/ScamFighter/packs` | Fetch URLs found in the scam body |
| DNSBL-check origin IPs | Open THESEE / FranceConnect for you |
| Draft `fraude@ovh.com` / ISP `abuse@` messages on disk | Auto-submit OVH / Pharos / THESEE web forms |
| Prepare a Spamhaus raw-`.eml` payload (dry-run) | Live Spamhaus POST without your phrase + env flag |
| Hand you a field map for Playwright assist | Mutate your mailbox |

Observe-first: every network submit is gated. Form plans set `auto_submit: false`.

## Prerequisites

1. At least one evidence pack (watcher with `--pack`, or `scamfighter pack …`).
2. Repo checkout with `uv` and Python 3.13+.
3. An MCP host (Cursor or Claude Desktop recommended).
4. Optional: `SPAMHAUS_API_TOKEN` only if you intend a live Spamhaus submit later.

```bash
ls ~/ScamFighter/packs   # note a case_id, e.g. 20260725-118849.…-0ef76786
```

## 1. Register the MCP server

Replace absolute paths with your machine’s.

### Cursor

Settings → MCP → add server, or merge into your MCP config:

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

Leave `SCAMFIGHTER_ALLOW_LIVE_SUBMIT` empty until you deliberately want a live
Spamhaus POST. Restart the agent / reload MCP so tools appear.

### Claude Desktop

Same JSON under `mcpServers` in `claude_desktop_config.json`, then restart Desktop.

### Sanity check

In chat, ask: *“List scamfighter-filing tools.”* You should see at least
`load_evidence_pack`, `enrich_ip_dnsbl`, `draft_mailto`, `get_form_fill_plan`,
`request_spamhaus_raw_email`, `confirm_filing_action`, `submit_spamhaus_raw_email`,
`filing_confirm_phrase`.

## 2. System / project instructions for the model

Paste this (or put it in a Cursor rule) so the model behaves safely:

```text
You are helping with ScamFighter evidence packs via the scamfighter-filing MCP.

Rules:
1. Only use packs under SCAMFIGHTER_PACKS (case_id or path inside that root).
2. Never fetch or open URLs from the scam message body. Defanged IOCs only.
3. Prefer draft_mailto and get_form_fill_plan over live submits.
4. For Spamhaus: request → show the operator the preview → wait for them to
   type the confirm phrase → dry_run submit first. Live submit only if they
   set SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1 and explicitly ask.
5. confirm_filing_action requires confirmation exactly I_CONFIRM_SUBMIT —
   do not invent confirmations; ask the human to type it.
6. Form plans are for assisted fill only (auto_submit is false). FranceConnect
   / THESEE login stays human.
```

## 3. Typical prompts (copy-paste)

Replace `CASE` with your pack’s `case_id` from `~/ScamFighter/packs/`.

### A. Brief the case

```text
Using scamfighter-filing, load_evidence_pack("CASE").
Summarize verdict, connecting_ip, BTC, and provenance notes.
Then enrich_ip_dnsbl on the connecting_ip.
Do not submit anything.
```

### B. Draft abuse email (OVH or ISP)

```text
Load pack CASE.
Call draft_mailto for to="fraude@ovh.com" lang="fr".
Then, if abuse emails exist on the connecting IP, draft_mailto to that address too.
Tell me the draft_path files written — I will send them myself.
```

### C. Prepare OVH / THESEE form assist

```text
For pack CASE, get_form_fill_plan("ovh_abuse") and get_form_fill_plan("thesee").
List the URLs, suggested fields, and attachments.
Do not open a browser or submit. I will copy the text into the sites myself
(or drive Playwright with auto_submit false).
```

### D. Spamhaus dry-run (safe default)

```text
For pack CASE:
1) request_spamhaus_raw_email with reason="sextortion mass campaign — unused BTC ransom"
2) Show me the preview (case_id, sha256, byte size). Stop.
When I am ready I will type I_CONFIRM_SUBMIT myself; then call
confirm_filing_action and submit_spamhaus_raw_email with dry_run=true.
```

### E. Live Spamhaus submit (operator only)

Only after dry-run looks correct:

1. Set in the MCP env: `SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1` and a real `SPAMHAUS_API_TOKEN`.
2. Reload MCP.
3. Prompt:

```text
Confirm token <TOKEN> with confirmation I_CONFIRM_SUBMIT
(I typed that phrase), then submit_spamhaus_raw_email(dry_run=false).
```

If the env flag is missing, submit must fail closed.

## 4. Tool sequence (reference)

```text
load_evidence_pack(case_id)
        │
        ├─► enrich_ip_dnsbl(connecting_ip)
        ├─► draft_mailto(case_id, to=…)          # writes draft_*.eml in pack dir
        ├─► get_form_fill_plan("ovh_abuse"|…)    # field map only
        │
        └─► request_spamhaus_raw_email(…)
                  │
                  ▼
            [human types I_CONFIRM_SUBMIT]
                  │
                  ▼
            confirm_filing_action(token, confirmation)
                  │
                  ▼
            submit_spamhaus_raw_email(token, dry_run=true)   # default
                  │
                  ▼ (optional, env + explicit ask)
            submit_spamhaus_raw_email(token, dry_run=false)
```

## 5. Pairing with Playwright (forms)

1. LLM calls `get_form_fill_plan("ovh_abuse", case_id)` and shows fields + local
   `message.eml` path.
2. You (or a Playwright MCP under your control) open the official HTTPS form URL
   from the plan — never a URL from the scam body.
3. Paste description from `complaint_fr.md` / plan fields; attach `message.eml`.
4. **You** click submit. Plans always include `"auto_submit": false`.

THESEE requires FranceConnect: the model may pre-fill text from the pack; login
and final send stay human.

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Pack not found / path outside packs | Use `case_id` under `SCAMFIGHTER_PACKS`, or set that env to your packs root |
| Confirm rejected | Phrase must be exactly `I_CONFIRM_SUBMIT` (see `filing_confirm_phrase`) |
| Live submit blocked | Set `SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1` and reload MCP |
| No Spamhaus token | Create a key at https://auth.spamhaus.org/account |
| Tools missing | Check `cwd` / `PYTHONPATH`; run `uv run --with mcp python -m scamfighter_filing_mcp` once in a terminal |

## Related

- Tool list & install notes: [`mcp_servers/filing/README.md`](../mcp_servers/filing/README.md)
- Where to file (OVH, THESEE, APIs): [FILING.md](FILING.md)
- Vulnerability reporting: [`SECURITY.md`](../SECURITY.md)
