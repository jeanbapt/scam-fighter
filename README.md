# ScamFighter

**Governed, defensive abuse-response toolkit for email extortion scams.**

ScamFighter helps individuals and small teams respond *lawfully* to mass-extortion
email (the “I RECORDED YOU” / sextortion class and relatives). It does not attack
anyone. It turns an incoming scam into structured evidence and prepares filings
for parties who may act: mailbox hosts, network `abuse@` contacts, Spamhaus, and
national complaint channels (e.g. THESEE in France).

> Defensive intermediary, not vigilante. No hack-back. Observe-only by default.

## What works today

- **Ingest** from a drop folder (Mail rule / export — least privilege), optional IMAP, or Apple Mail store (advanced; Full Disk Access).
- **Deterministic analysis**: sextortion classifier, SPF/DKIM/DMARC, BTC / IP / URL IOCs.
- **Watch folder**: poll inbox → analyze → optional evidence pack → move to processed.
- **Write-once vault** (SHA-256) + **FR/EN complaint packs** with provenance (RDAP / DNS / BTC).
- **Filing MCP** (observe-first): DNSBL lookup, mailto drafts, confirm-gated Spamhaus prepare; form field maps for OVH / Pharos / THESEE (no auto-submit).

## What it will never do

- No unauthorized access to third-party systems (“hack-back”) — see [`docs/LEGAL.md`](docs/LEGAL.md).
- No harassment or automated engagement with scammers.
- No silent cloud offload of mailbox content — local-first; cloud LLM only behind ShieldFlow when you opt in.

## Why it is safe by design

Side effects that leave the machine go through governance / explicit operator gates
(local audit, confirm phrases, env opt-in for live submits). Hostile mail is parsed
without fetching body URLs or executing attachments. See
[`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Stack

- Python 3.13+, `uv`
- `scamfighter_core` library + `scamfighter_app` CLI
- Optional MCP (`mcp_servers/filing`) for model-assisted filing prep
- Filesystem evidence vault under `~/ScamFighter/` (gitignored)

## Repository layout

```
apps/           # CLI (ingest / watch / pack)
packages/       # scamfighter_core
mcp_servers/    # filing MCP (+ placeholders)
policies/       # governance policies
schemas/        # schemas
docs/           # architecture, legal, filing, threat model
tests/          # unit tests + sanitized fixtures
```

## Quickstart

```bash
cp .env.example .env
export PYTHONPATH=packages/scamfighter_core:apps/scamfighter

uv run --with pytest pytest -q
uv run --with ruff ruff check packages apps tests mcp_servers/filing
uv run --with mypy mypy packages/scamfighter_core/scamfighter_core apps/scamfighter/scamfighter_app

# Analyze Mail-rule exports (no Full Disk Access):
uv run python -m scamfighter_app ingest --source folder

# Hands-off watcher (detect → analyze → pack → move):
uv run python -m scamfighter_app watch --move-processed --pack

# Pack only:
uv run python -m scamfighter_app pack --path ~/ScamFighter/processed
```

macOS Mail setup: [docs/MACOS_MAIL.md](docs/MACOS_MAIL.md)  
Filing channels: [docs/FILING.md](docs/FILING.md)  
LLM + filing MCP: [docs/MCP_FILING.md](docs/MCP_FILING.md)  
MCP install: [mcp_servers/filing/README.md](mcp_servers/filing/README.md)

## Documentation

| Doc | Topic |
|-----|--------|
| [PRD.md](PRD.md) | Product intent |
| [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Roadmap |
| [docs/MACOS_MAIL.md](docs/MACOS_MAIL.md) | Apple Mail (least privilege first) |
| [docs/FILING.md](docs/FILING.md) | OVH, THESEE, APIs vs forms |
| [docs/MCP_FILING.md](docs/MCP_FILING.md) | LLM + filing MCP how-to |
| [docs/GOVERNANCE.md](docs/GOVERNANCE.md) | Approval / audit boundary |
| [docs/LEGAL.md](docs/LEGAL.md) | Legal posture |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |

## Status

Active development (Phase 1). Core ingest / watch / vault / pack / filing helpers
are usable locally. Broader agents, ARF/STIX exporters, and clustering are on the
roadmap — see the PRD and implementation plan.

## License

[MIT](LICENSE) © 2026 ScamFighter contributors
