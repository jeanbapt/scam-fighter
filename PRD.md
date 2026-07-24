# ScamFighter PRD v0.3

## Vision
ScamFighter is an open-source, governed, **defensive** abuse-response and evidence
toolkit for mass email extortion campaigns (the "I RECORDED YOU" / sextortion
class and relatives). It converts incoming scams into court-credible evidence and
standards-based abuse reports routed to the parties allowed to act (email/hosting
providers, registrars, CERTs, law enforcement). It is a defensive intermediary,
never a vigilante tool.

## Non-negotiable posture
- Observe-only by default
- No hack-back / no unauthorized access to any system
- No harassment of or automated engagement with scammers
- Email content stays local by default (privacy + lawful processing)
- Immutable, chain-of-custody evidence
- Typed models everywhere
- Every side effect passes through the governance boundary

See `docs/LEGAL.md` for the legal basis and boundaries.

## Core stack
- Python 3.13+
- PydanticAI (typed agents)
- FastAPI
- MCP (stdio, local-first)
- uv
- Strict YAML -> Pydantic models
- SQLite (local first)
- Local filesystem evidence vault (append-only)

## AI models (edge-first)
This is a text-classification + indicator-extraction + clustering problem. Reliability
order: deterministic parsers > small classifiers/embeddings > LLM reasoning.

- Deterministic first: regex/parser IOC extraction, SPF/DKIM/DMARC, RDAP/WHOIS.
- Default reasoning: local edge LLM (e.g. LiquidAI LFM2, Qwen2.5 small, Gemma, Phi).
- Fallback: Ollama local.
- Escalation: Ollama Cloud via `OLLAMA_API_KEY` — **opt-in per case**, never a silent
  fallback, because it moves PII off-device.
- Similarity: small local embedding model + cosine.

Removed from scope: the experimental "pythonic tool-call adapter (AST-parsed)".
Executing model-authored code paths near live malicious content is needless attack
surface for a hardened tool. Tool-calling uses fixed, typed schemas only.

## Governance (was: SGRS)
Governance is a **pluggable boundary**, not a hard dependency:
- `Governance` Protocol in `scamfighter_core`: validated state machine + approval
  gate + tamper-evident audit log.
- Phase 1 ships `LocalGovernance` (stdlib only).
- SGRS (or any engine) can be added later as an adapter behind `Governance` without
  changing agents or MCP servers.

ScamFighter never reimplements a governance engine in agents/connectors; they only
depend on the `Governance` Protocol. See `docs/GOVERNANCE.md`.

## Architecture
```
OVH IMAP
 -> Intake Agent
 -> Campaign Analyzer
 -> Similarity Hunter
 -> Evidence Builder
 -> Planner
 -> Approval (human / policy gate)
 -> Governance (state transition + audit)
 -> MCP connectors
```

## MCP servers
- mail-read (read-only IMAP)
- mail-actions (label/quarantine your own mail; gated; disabled in observe mode)
- evidence (write-once vault)
- reporting (ARF/X-ARF, STIX, RDAP-routed referrals)
- threat-intel (public lookups only)

## Evidence & reporting standards
- Preserve raw `.eml` + full headers, SHA-256 hashed, write-once.
- Chain-of-custody metadata; RFC 3161 trusted timestamps (or transparency-log anchor).
- ARF / X-ARF for provider abuse reports.
- STIX 2.1 (optionally over TAXII) for CERT / threat-intel sharing.
- RDAP-driven routing to the correct `abuse@` contact.
- Templated referrals for IC3 / national CERT / police with the case bundle.
- Crypto-address reporting (Chainabuse / exchange abuse desks).
- Defang all indicators in reports (`hxxp://`, `evil[.]com`).

## Security & supply chain
- Signed commits, CODEOWNERS, branch protection, required reviews
- Committed lockfile; pinned dependencies; Dependabot
- OSV Scanner, pip-audit, CodeQL, Semgrep, OpenSSF Scorecard
- Least-privilege GITHUB_TOKEN; secret scanning + push protection
- SBOM; Sigstore provenance
- Treat all ingested content as hostile: no URL auto-fetch, no attachment
  execution/rendering, sandboxed parsing, fuzzed parsers. See `docs/THREAT_MODEL.md`.

## Repository
```
apps/ packages/ mcp_servers/ policies/ schemas/ docs/ tests/
```

## Contribution model
Open contribution (anyone may PR), gated trust (vetted maintainers merge; signed
commits; CODEOWNERS on sensitive areas). See `CONTRIBUTING.md`.

## Local mode
Everything runs locally: SQLite, filesystem evidence, stdio MCP servers, edge
models. Optional opt-in Ollama Cloud escalation.

## Roadmap
- Phase 1: Local MVP (ingest -> evidence -> plan; observe-only)
- Phase 2: Web UI (case queue, evidence viewer, approvals)
- Phase 3: Reporting integrations (real ARF/STIX/registrar backends)
- Phase 4: Multi-provider mail (beyond OVH IMAP)
- Phase 5: Enterprise deployment (hardened, SSO, multi-tenant)
