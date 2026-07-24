# Running ScamFighter on top of macOS Mail

ScamFighter can analyze the mail already sitting in Apple Mail (Mail.app) on your
Mac, fully locally and read-only. This page explains what that takes.

## How Apple Mail stores messages

Mail.app keeps every message as an individual `.emlx` file under:

```
~/Library/Mail/V10/<AccountUUID>/<Mailbox>.mbox/.../Data/.../Messages/<id>.emlx
```

- The `V10` version segment changes with macOS releases (`V9`, `V10`, ...).
  ScamFighter auto-detects the newest `V*` via `default_mac_mail_root()`.
- An `.emlx` file is a normal RFC 822 message wrapped in a tiny frame: a first
  line with the byte count, the raw message, then an Apple plist of flags.
  `scamfighter_core.parse_emlx()` strips the frame; the rest of the pipeline is
  identical to any other mail source.

Because we read the on-disk store, **no account password is needed** and nothing
is fetched over the network.

## The one requirement: Full Disk Access

`~/Library/Mail` is protected by macOS TCC. The process that runs ScamFighter (your
terminal app, e.g. Terminal, iTerm, or the IDE) must be granted **Full Disk
Access**:

1. System Settings -> Privacy & Security -> Full Disk Access.
2. Enable your terminal/IDE app.
3. Restart that app so the permission takes effect.

Without it, the mail directory appears empty (you'll see "No Apple Mail store
found" or zero messages).

## Run it

```bash
# From the repo root
export PYTHONPATH=packages/scamfighter_core:apps/scamfighter

# Analyze the newest Mail store, observe-only, deterministic verdicts:
uv run python -m scamfighter_app ingest --source macmail --limit 50

# Point at a specific version/mailbox:
uv run python -m scamfighter_app ingest --source macmail --path "~/Library/Mail/V10"

# Also draft victim-friendly summaries with the LOCAL model (Ollama):
uv run python -m scamfighter_app ingest --source macmail --summarize

# Escalate summaries to a guarded cloud model (routed through ShieldFlow):
export SCAMFIGHTER_CLOUD_API_KEY=...        # OpenAI-compatible key
uv run python -m scamfighter_app ingest --source macmail --summarize --escalate
```

Sample output:

```
[SCAM] sextortion (1.00) | [SPAM] I RECORDED YOU!
    from=you@example.com to=you@example.com self_addressed=True
    auth: spf=softfail dkim=none dmarc=fail (all_failing=True)
    btc: 1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS
    origin_ips: 213.230.87.82
    urls: hxxp://www[.]coinbase[.]com, ...
```

## What runs where

- **Ingest + parse + classify**: 100% local, deterministic (no model). The
  sextortion verdict comes from headers + indicators, not an LLM.
- **Summaries (`--summarize`)**: local Ollama by default.
- **Cloud escalation (`--escalate`)**: only when asked; the prompt is redacted
  in-process and routed through the ShieldFlow local proxy (PII tokenized in
  transit). If ShieldFlow is not active, escalation **fails closed**.

## Alternatives to reading the store directly

- **AppleScript / JXA** (`osascript`) can ask Mail.app for messages without Full
  Disk Access, but it is slower, requires Automation permission, and returns less
  faithful headers. The `.emlx` reader is preferred for evidence fidelity.
- **IMAP** (`--source imap`): connect to the same account read-only
  (`BODY.PEEK`, `readonly=True`) instead of touching Mail.app at all. Good when
  ScamFighter runs on a server rather than your Mac.

## Safety notes

- Reading is **read-only**; ScamFighter never marks messages read, moves, or
  deletes anything. Quarantine/label actions are a separate, governed capability
  (Phase 1 keeps them disabled in observe mode).
- Real messages contain PII; keep any exported evidence in the git-ignored
  `samples/`/vault locations, never in the repo.
