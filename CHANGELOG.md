# Changelog

All notable changes to ScamFighter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-25

### Added

- Deterministic email ingest and sextortion analysis (folder / IMAP / macOS Mail).
- Hands-off `watch` with detect → analyze → evidence pack → move-processed.
- Write-once SHA-256 evidence vault and FR/EN complaint packs + provenance.
- Filing helpers and observe-first MCP (`scamfighter-filing`): DNSBL, mailto drafts,
  confirm-gated Spamhaus prepare, form field maps.
- Local governance audit chain, ShieldFlow-gated cloud LLM path, egress audit labels.
- CI: ruff, mypy, pytest, pip-audit, CodeQL, Semgrep, OSV, gitleaks, dependency-review,
  OpenSSF Scorecard (SHA-pinned actions).
- Docs: macOS Mail, filing channels, LLM+MCP guide, legal / threat model / governance.
- Community files: MIT license, CONTRIBUTING, Code of Conduct, SECURITY.

### Security

- Hostile-input bounds on ingest; packs-root containment for filing MCP.
- Live Spamhaus submit requires `I_CONFIRM_SUBMIT` and `SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1`.

[0.1.0]: https://github.com/jeanbapt/scam-fighter/releases/tag/v0.1.0
