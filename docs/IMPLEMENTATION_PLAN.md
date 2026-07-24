# ScamFighter Implementation Plan

Derived from [PRD v0.2](../PRD.md). Goal: ship a **local MVP** (Phase 1) that can ingest OVH IMAP mail, analyze campaigns, build immutable evidence, propose actions, and execute only through **SGRS-governed** MCP connectors — observe-only by default.

## Principles (non-negotiable)

| Rule | Implication |
|------|-------------|
| Observe-only by default | Mail mutations and external reports require explicit approval + SGRS transition |
| No hack-back | MCP tool surface is defensive only (read, quarantine/label, report, evidence) |
| Never reimplement SGRS | Depend on public SGRS runtime/client; ScamFighter only supplies policies + payloads |
| Typed everything | Strict YAML → Pydantic models; no untyped agent I/O |
| Local-first | SQLite, filesystem vault, stdio MCP; cloud LLMs are escalation only |
| Immutable evidence | Append-only vault; content-addressed artifacts; no in-place edits |

## Target architecture

```text
OVH IMAP
  -> Intake Agent
  -> Campaign Analyzer
  -> Similarity Hunter
  -> Evidence Builder
  -> Planner
  -> Approval (human / policy gate)
  -> SGRS Governance
  -> MCP connectors
       mail-read | mail-actions | evidence | reporting | threat-intel
```

**Runtime shape (Phase 1):** FastAPI orchestrator + PydanticAI agents + SGRS client + five stdio MCP servers + SQLite + `./evidence` vault.

**AI routing:** LiquidAI LFM2.5 local (default) → Ollama local/Qwen (fallback) → Ollama Cloud via `OLLAMA_API_KEY` (escalation). Experimental: LiquidAI pythonic tool-call adapter (AST-parsed, never `eval`).

---

## Workstreams

### WS0 — Repository & engineering baseline (week 0)

- [x] Git repo, `.gitignore`, MIT license, `CODEOWNERS`, `.env.example`, layout scaffold
- [ ] `uv` workspace: `apps/scamfighter`, `packages/scamfighter_core`, `mcp_servers/*`
- [ ] Pin Python 3.13+, ruff, mypy, pytest
- [ ] CI skeleton: lint + typecheck + unit tests
- [ ] Security CI stubs (enable as code lands): dependency-review, OSV, pip-audit, CodeQL, Semgrep, SBOM, Sigstore provenance
- [ ] Require signed commits on `main` (GitHub branch protection)
- [ ] Document how to point at the public SGRS client package/repo

**Exit:** `uv sync` + empty CI green; SGRS client importable as a dependency.

### WS1 — Schemas, config, storage

- [ ] Pydantic models for: message, campaign, similarity hit, evidence package, plan, approval decision, action proposal
- [ ] Strict YAML schemas under `schemas/` with loaders that fail closed
- [ ] SQLite schema: messages, campaigns, evidence_refs, plans, approvals, audit_events
- [ ] Filesystem evidence vault API: write-once, hash (SHA-256), path layout, retention metadata
- [ ] Settings from env (see `.env.example`); `SCAMFIGHTER_MODE=observe|approve|act`

**Exit:** Can persist a synthetic message + evidence blob and reload typed models.

### WS2 — MCP servers (capability isolation)

Implement stdio MCP servers under `mcp_servers/`:

| Server | Phase 1 scope |
|--------|----------------|
| `mail-read` | IMAP fetch/list/search (OVH); no mutations |
| `mail-actions` | Label/move/quarantine only; gated; disabled in observe mode |
| `evidence` | Vault put/get/list; never overwrite |
| `reporting` | Stub: emit local report artifact (external APIs in Phase 3) |
| `threat-intel` | Stub: local lookups / placeholder providers |

- [ ] Shared MCP packaging pattern (one entrypoint each)
- [ ] Hard deny of tools not allowed by mode + SGRS
- [ ] Integration tests with mocked IMAP / temp vault

**Exit:** Agents can call `mail-read` + `evidence` end-to-end locally; `mail-actions` refuse in observe mode.

### WS3 — SGRS integration

- [ ] Wire public SGRS client; load policies from `policies/`
- [ ] Model state machine for case lifecycle (e.g. `ingested → analyzed → evidenced → planned → approved → executed → closed`)
- [ ] Every transition produces an audit event in SQLite
- [ ] Action proposals cannot reach MCP `mail-actions` / `reporting` without a valid SGRS transition + approval record

**Exit:** Unauthorized transition rejected; authorized path reaches MCP once.

### WS4 — Agent pipeline (PydanticAI v2)

Implement agents as typed steps (structured outputs only):

1. **Intake** — normalize IMAP message → `Message` model  
2. **Campaign Analyzer** — cluster/classify abuse pattern → `Campaign`  
3. **Similarity Hunter** — find related messages in SQLite vault → `SimilarityHit[]`  
4. **Evidence Builder** — assemble package + write vault via MCP → `EvidencePackage`  
5. **Planner** — propose defensive actions → `Plan` (observe annotations if mode=observe)  
6. **Approval** — human or policy gate → `ApprovalDecision`  

- [ ] Provider router: LiquidAI → Ollama local → Ollama Cloud
- [ ] Optional experimental LiquidAI pythonic tool-call path behind a feature flag
- [ ] FastAPI routes: health, ingest trigger, case status, approve plan

**Exit:** One real or fixture mailbox path produces a plan + evidence without mutating mail.

### WS5 — Local MVP vertical slice (Phase 1 done)

- [ ] CLI or API: `ingest` → full pipeline → plan awaiting approval  
- [ ] Manual approval → SGRS → (still observe: log intended actions only)  
- [ ] Toggle `approve`/`act` for quarantining a labeled test folder only  
- [ ] README quickstart: OVH IMAP, local models, vault path  
- [ ] Minimal e2e test with fixtures (no live IMAP required in CI)

**Exit criteria (Phase 1):** Developer can run ScamFighter fully offline (except optional cloud LLM), process mail, store immutable evidence, and never mutate mail unless mode + SGRS + approval allow it.

---

## Later phases (out of Phase 1 scope)

| Phase | Focus | Depends on |
|-------|--------|------------|
| **2 — Web UI** | Case queue, evidence viewer, approval UX | Stable API + schemas |
| **3 — Reporting integrations** | Real `reporting` MCP backends | Phase 1 vault + SGRS |
| **4 — Multi-provider mail** | Beyond OVH IMAP | `mail-read`/`mail-actions` abstractions |
| **5 — Enterprise deployment** | Hardened deploy, SSO, multi-tenant | Phases 2–4 |

---

## Suggested build order (milestones)

```text
M0  Repo + uv + CI + SGRS dependency
M1  Schemas + SQLite + evidence vault
M2  mail-read + evidence MCP
M3  SGRS policies + gated transitions
M4  Intake → Analyzer → Similarity → Evidence agents
M5  Planner + Approval + FastAPI
M6  mail-actions (gated) + mode matrix tests
M7  Phase 1 polish: docs, e2e fixtures, security scanners on
```

## Risks & open decisions

1. **SGRS package coordinates** — Confirm public repo/package name and policy DSL version before WS3.  
2. **LiquidAI LFM2.5 local runtime** — Confirm install/runtime API for default provider; keep Ollama as mandatory fallback.  
3. **IMAP auth** — Prefer app passwords / OAuth if OVH supports; never commit secrets.  
4. **Similarity** — Start with deterministic features (headers, domains, URLs, hashes); add embeddings later if needed.  
5. **Approval UX** — Phase 1 can be CLI/API-only; defer rich UI to Phase 2.

## Definition of done (repo-level, ongoing)

- Typed models for all agent I/O  
- Observe-only default verified by tests  
- Evidence write-once verified by tests  
- SGRS is the only path to side-effecting MCP tools  
- Security tooling from PRD enabled before first public release tag
