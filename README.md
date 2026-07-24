# ScamFighter

**A governed, defensive abuse-response and evidence toolkit for email extortion scams.**

ScamFighter helps individuals and small teams respond *lawfully* to mass-extortion
email campaigns — the "I RECORDED YOU" / sextortion class and its relatives. It
does not attack anyone. It turns an incoming scam into structured, court-credible
evidence and routes standards-based abuse reports to the parties who are actually
allowed to act: email providers, hosting providers, domain registrars, national
CERTs, and law enforcement.

> Defensive intermediary, not vigilante. No hack-back. Observe-only by default.

## What it does

- **Ingest** scam mail from IMAP (local-first, read-only by default).
- **Analyze** the campaign: classify the scam type, verify SPF/DKIM/DMARC, extract
  indicators (crypto addresses, URLs, sender infrastructure).
- **Cluster** related messages to see the campaign, not just one email.
- **Build immutable evidence**: original `.eml`, full headers, hashes, chain of
  custody, trusted timestamps.
- **Propose** defensive actions (label/quarantine your own mail; draft abuse
  reports) — never executed without an approval and a governed state transition.
- **Report** in formats the recipients already ingest: ARF / X-ARF, STIX 2.1,
  RDAP-routed `abuse@` referrals, and templated law-enforcement submissions.

## What it will never do

- No unauthorized access to any system ("hack-back") — see [`docs/LEGAL.md`](docs/LEGAL.md).
- No harassment or automated engagement with scammers.
- No silent exfiltration of email content to the cloud — see privacy in [`docs/LEGAL.md`](docs/LEGAL.md).

## Why it is safe by design

Every side-effecting action passes through a **governance boundary** (validated
state machine + approval gate + tamper-evident audit log). Phase 1 ships a
dependency-free `LocalGovernance`; other engines can be added as adapters without
touching agents or connectors. See [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md).

## Models: edge-first

This is a text-classification + indicator-extraction + clustering problem, so it
runs on **small local models** by default (privacy, cost, reproducibility). Cloud
models are opt-in escalation for the hard minority of cases only. See
[`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md#models).

## Stack

- Python 3.13+, `uv`
- PydanticAI (typed agents) with an edge-first provider router
- MCP servers (stdio, local-first) for capability isolation
- SQLite + append-only filesystem evidence vault

## Repository layout

```
apps/           # runnable application(s)
packages/       # shared libraries (scamfighter_core: models + governance)
mcp_servers/    # mail-read, mail-actions, evidence, reporting, threat-intel
policies/       # governance policies
schemas/        # strict YAML + Pydantic schemas
docs/           # architecture, governance, legal, threat model, plan
tests/          # unit, integration, e2e
```

## Quickstart (developers)

```bash
cp .env.example .env
uv run --with pytest pytest -q      # run the test suite

# Apple Mail, the safe way: a Mail rule auto-exports matches into ~/ScamFighter/inbox
# (no Full Disk Access, no IMAP; see docs/MACOS_MAIL.md), then:
export PYTHONPATH=packages/scamfighter_core:apps/scamfighter
uv run python -m scamfighter_app ingest --source folder

# Or leave a hands-off watcher running that analyzes new drops in real time:
uv run python -m scamfighter_app watch

# Or read Apple Mail's on-disk store directly (advanced; needs Full Disk Access)
uv run python -m scamfighter_app ingest --source macmail --limit 50
```

See [docs/MACOS_MAIL.md](docs/MACOS_MAIL.md) for running on top of macOS Mail.

## Documentation

- [PRD](PRD.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Running on macOS Mail](docs/MACOS_MAIL.md)
- [Governance model](docs/GOVERNANCE.md)
- [Legal basis and boundaries](docs/LEGAL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security policy](SECURITY.md) | [Contributing](CONTRIBUTING.md) | [Code of Conduct](CODE_OF_CONDUCT.md)

## Status

Pre-implementation (Phase 1 in progress). Contributions welcome under an
open-contribution, gated-trust model — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
