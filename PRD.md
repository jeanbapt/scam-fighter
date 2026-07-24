# ScamFighter PRD v0.2

## Vision
ScamFighter is an open-source defensive email abuse response platform built as the first production application on top of SGRS.

## Core stack
- Python 3.13+
- PydanticAI v2
- SGRS client (public repo)
- FastAPI
- MCP
- uv
- Strict YAML -> Pydantic models
- SQLite (local first)
- Local filesystem evidence vault

## AI providers
Default:
- LiquidAI LFM2.5 local
Fallback:
- Ollama local (Qwen)
Escalation:
- Ollama Cloud using OLLAMA_API_KEY

Experimental:
- LiquidAI Pythonic tool-call adapter (AST parsed, never eval)

## Architecture
OVH IMAP
 -> Intake Agent
 -> Campaign Analyzer
 -> Similarity Hunter
 -> Evidence Builder
 -> Planner
 -> Approval
 -> SGRS Governance
 -> MCP connectors

## MCP
- mail-read
- mail-actions
- evidence
- reporting
- threat-intel

## SGRS
Reuse public SGRS runtime and client.
ScamFighter never reimplements governance.

## Security
- Observe-only by default
- No hack-back
- Immutable evidence
- Typed models everywhere
- Signed commits
- CODEOWNERS
- Dependency review
- OSV Scanner
- pip-audit
- CodeQL
- Semgrep
- SBOM
- Sigstore provenance

## Repository
apps/
packages/
mcp_servers/
policies/
schemas/
docs/
tests/

## Local mode
Everything runs locally:
- SQLite
- filesystem evidence
- stdio MCP servers
- optional Ollama Cloud escalation

## Roadmap
Phase 1: Local MVP
Phase 2: Web UI
Phase 3: Reporting integrations
Phase 4: Multi-provider mail
Phase 5: Enterprise deployment
