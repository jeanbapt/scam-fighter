# ScamFighter Implementation Plan

Derived from [PRD v0.3](../PRD.md). Goal: ship a **local MVP** (Phase 1) that
ingests OVH IMAP mail, analyzes campaigns, builds immutable evidence, proposes
defensive actions, and executes only through a **governed** boundary with recorded
approval — observe-only by default.

## Principles (non-negotiable)

| Rule | Implication |
|------|-------------|
| Observe-only by default | Mail mutations and outbound reports require approval + a governed transition |
| No hack-back | MCP tool surface is defensive only (read, quarantine own mail, report, evidence) |
| Governance is a boundary | Depend on the `Governance` Protocol; SGRS/others are optional adapters |
| Typed everything | Strict YAML -> Pydantic models; no untyped agent I/O |
| Edge-first models | Deterministic parsers > small models; cloud is opt-in escalation |
| Local-first | SQLite, filesystem vault, stdio MCP; email content stays on-device |
| Immutable evidence | Append-only vault; content-addressed; hash-chained audit |

## Target architecture

```text
OVH IMAP
  -> Intake Agent
  -> Campaign Analyzer
  -> Similarity Hunter
  -> Evidence Builder
  -> Planner
  -> Approval (human / policy gate)
  -> Governance (validated transition + audit)
  -> MCP connectors
       mail-read | mail-actions | evidence | reporting | threat-intel
```

## Models

Reliability order: **deterministic parsers > small classifiers/embeddings > LLM
reasoning.** Right-size each task:

| Task | Right tool | Why |
|------|-----------|-----|
| IOC extraction (crypto addrs, URLs, emails, headers) | Regex / deterministic parsers | Zero hallucination, auditable, court-credible |
| Auth checks (SPF/DKIM/DMARC, RDAP/WHOIS) | Library calls | Facts, not inference |
| Scam-type classification | Small local classifier or edge LLM (LFM2, Qwen2.5-1.5B/3B, Gemma, Phi) | Cheap, private, sufficient |
| Campaign clustering / similarity | Small local embedding model + cosine | Runs on a laptop |
| Evidence summary / draft abuse report | Edge LLM; cloud escalation opt-in | Only place a bigger model marginally helps |

Provider router: edge LLM (default) -> Ollama local (fallback) -> Ollama Cloud
(opt-in per case, `OLLAMA_API_KEY`). No model-authored code execution; tool-calls
use fixed typed schemas only. The experimental pythonic tool-call adapter is out.

Candidate edge models (all on-device, permissive-until-scale license): LiquidAI
LFM2.5-350M / 1.2B for reasoning; LFM2.5-Embedding-350M or ColBERT-350M for
similarity clustering; small Qwen/Gemma/Phi as alternates via Ollama.

### Cloud egress guard (PII + prompt injection)

Cloud escalation must never leak PII (`docs/LEGAL.md`: no silent cloud offload),
and the scam body is attacker-controlled text, so escalating it is also a
prompt-injection vector (`docs/THREAT_MODEL.md`). Both risks share one chokepoint:
the **egress guard** every cloud-bound string passes through. It **fails closed** —
if the guard cannot vouch for the text, it is not sent.

Implemented in `scamfighter_core.egress_guard` as a pluggable `EgressGuard`
boundary (same pattern as `Governance`) with two layers:

1. **`DeterministicRedactor`** (always on, no model): reliably masks structured PII
   — emails, phone-like numbers, IPs, crypto addresses, URLs. It never claims to
   cover free-text PII or injection (`semantic_pii_checked=False`).
2. **Semantic guard** for free-text PII (names, addresses) and injection detection.

In `strict` mode (`CompositeEgressGuard(strict=True)`), deterministic redaction
alone is **not** sufficient to clear text for the cloud — a semantic guard must
vet it. Use `guard_cloud_egress(text, guard)` at every cloud call site.

**Chosen semantic guard: LiquidAI ShieldFlow (local egress proxy).** ShieldFlow
installs as a **local MITM proxy** (loopback port + CA bundle), not an in-process
library. It tokenizes PII in outbound LLM API traffic (reversible-by-default) for
many providers (OpenAI, Anthropic, Azure, Bedrock, Groq, Mistral, OpenRouter,
Perplexity, DeepSeek, GitHub Models, Cursor, ...) per its synced policy, and blocks
prompt injection — covering both egress risks on the wire.

Integration (`scamfighter_core.shieldflow`):

- `load_config()` discovers the proxy URL + CA bundle from the environment or
  `~/.shieldflow/proxy_env.sh` (no secrets read).
- `is_active(cfg)` health-checks the proxy (reachable port + fresh heartbeat).
- `httpx_transport(cfg)` / `requests_transport(cfg)` return the kwargs to route a
  cloud LLM client through ShieldFlow (proxy + CA bundle) — **required** for the
  tokenization to actually apply.
- `ShieldFlowGuard.discover()` is the `EgressGuard`: it certifies protection is
  live (`semantic_pii_checked=True`) or **fails closed** if the proxy is down. It
  does not alter text; redaction happens in transit.

Because protection is at the transport layer, the rule is: **route every cloud LLM
call through `httpx_transport`/`requests_transport`, and gate it with the composite
guard.** Deterministic in-process redaction remains an independent second layer.

LiquidAI PII lineup for reference:

| Option | Status | Role here |
|--------|--------|-----------|
| **ShieldFlow (LFM PII)** | Access-gated; access obtained | **Primary semantic egress guard** (PII + injection) |
| **LFM2-350M-PII-Extract-JP** | Open weights (HF + GGUF), 350M | Japanese-only; use only for JP mail |
| **LFM2-350M/1.2B-Extract** | Deprecated | Not a redactor |

Fallback semantic guards (swappable behind `EgressGuard`) if ShieldFlow is
unavailable in a given deployment: OpenAI Privacy Filter (open weights) or
Microsoft Presidio.

## Workstreams

### WS0 - Repository & engineering baseline (week 0)

- [x] Git repo, `.gitignore`, MIT license, `CODEOWNERS`, `.env.example`, layout
- [x] `Governance` Protocol + `LocalGovernance` in `scamfighter_core` (+ tests)
- [x] Governance / Legal / Threat-model / Security / Contributing / CoC docs
- [x] CI: lint + typecheck + unit tests; Dependabot; least-privilege tokens
- [ ] Enable security scanners as code lands: OSV, pip-audit, CodeQL, Semgrep,
      OpenSSF Scorecard, SBOM, Sigstore provenance
- [ ] Branch protection on `main`: signed commits, required reviews, required checks
- [ ] Commit lockfile once resolvable in CI (`uv.lock`)

**Exit:** clean checkout builds and tests green with no insider knowledge.

### WS1 - Schemas, config, storage

- [ ] Pydantic models: message, campaign, similarity hit, evidence package, plan,
      approval decision, action proposal
- [ ] Strict YAML schemas under `schemas/` with fail-closed loaders
- [ ] SQLite schema: messages, campaigns, evidence_refs, plans, approvals, audit
- [ ] Filesystem evidence vault: write-once, SHA-256, path layout, retention metadata
- [ ] Settings from env; `SCAMFIGHTER_MODE=observe|approve|act`

**Exit:** persist a synthetic message + evidence blob and reload typed models.

### WS2 - MCP servers (capability isolation)

| Server | Phase 1 scope |
|--------|----------------|
| `mail-read` | IMAP fetch/list/search (OVH); no mutations |
| `mail-actions` | Label/move/quarantine own mail only; gated; disabled in observe mode |
| `evidence` | Vault put/get/list; never overwrite |
| `reporting` | Emit local ARF/X-ARF + STIX artifacts; external delivery in Phase 3 |
| `threat-intel` | Public lookups / placeholders only |

- [ ] Shared MCP packaging pattern (one entrypoint each)
- [ ] Hard deny of tools not allowed by mode + governance
- [ ] Integration tests with mocked IMAP / temp vault; treat all input as hostile

**Exit:** `mail-read` + `evidence` work end-to-end locally; `mail-actions` refuses
in observe mode.

### WS3 - Governance integration

- [x] `Governance` boundary defined and tested (`LocalGovernance`)
- [ ] Load policies from `policies/`
- [ ] Persist state + audit in SQLite (durable backend behind same interface)
- [ ] Action proposals cannot reach `mail-actions` / `reporting` without a valid
      transition + approval record
- [ ] (Optional, later) `SgrsGovernance` adapter behind the same Protocol

**Exit:** unauthorized transition rejected; authorized path reaches MCP once.

### WS4 - Agent pipeline (PydanticAI)

Typed steps, structured outputs only:

1. **Intake** - normalize IMAP message -> `Message`
2. **Campaign Analyzer** - classify + SPF/DKIM/DMARC -> `Campaign`
3. **Similarity Hunter** - related messages -> `SimilarityHit[]`
4. **Evidence Builder** - assemble + write vault via MCP -> `EvidencePackage`
5. **Planner** - propose defensive actions -> `Plan` (observe annotations in observe mode)
6. **Approval** - human/policy gate -> `ApprovalDecision`

- [ ] Provider router (edge -> Ollama local -> opt-in cloud)
- [ ] FastAPI routes: health, ingest trigger, case status, approve plan

**Exit:** one mailbox path (fixture or real) produces a plan + evidence without
mutating mail.

### WS5 - Local MVP vertical slice (Phase 1 done)

- [ ] CLI/API: `ingest` -> pipeline -> plan awaiting approval
- [ ] Manual approval -> governance -> (observe: log intended actions only)
- [ ] Toggle `approve`/`act` for quarantining a labeled test folder only
- [ ] README quickstart: OVH IMAP, local models, vault path
- [ ] Minimal e2e test with fixtures (no live IMAP in CI)

**Exit (Phase 1):** run fully offline (except opt-in cloud LLM), process mail,
store immutable evidence, never mutate mail unless mode + governance + approval
allow it.

## Evidence & reporting (standards-based)

- Preserve raw `.eml` + full headers; SHA-256; write-once; RFC 3161 timestamps.
- Chain-of-custody metadata (who/what/when/tool version/hash tree).
- **ARF / X-ARF** for provider abuse reports.
- **STIX 2.1** (optionally over TAXII) for CERT / threat-intel sharing.
- **RDAP-driven** routing to the correct `abuse@` contact.
- Templated **IC3 / national CERT / police** referrals with the case bundle.
- **Crypto-address** reporting (Chainabuse / exchange abuse desks).
- **Defang** all indicators in reports (`hxxp://`, `evil[.]com`).

## Suggested milestones

```text
M0  Repo + governance boundary + CI + docs        [done]
M1  Schemas + SQLite + evidence vault
M2  mail-read + evidence MCP
M3  Governance policies + gated transitions (SQLite-backed)
M4  Intake -> Analyzer -> Similarity -> Evidence agents
M5  Planner + Approval + FastAPI
M6  mail-actions (gated) + mode-matrix tests
M7  Phase 1 polish: docs, e2e fixtures, security scanners on
```

## Risks & open decisions

1. **SGRS coordinates** - if/when a public SGRS exists, add it as an adapter; the
   core no longer blocks on it.
2. **Edge model runtime** - confirm LiquidAI LFM2 local runtime; keep Ollama as a
   mandatory fallback.
3. **IMAP auth** - prefer app passwords / OAuth; never commit secrets.
4. **Similarity** - start deterministic (headers, domains, URLs, hashes); add
   embeddings if needed.
5. **Approval UX** - CLI/API in Phase 1; rich UI in Phase 2.

## Definition of done (repo-level, ongoing)

- Typed models for all agent I/O
- Observe-only default verified by tests
- Evidence write-once verified by tests
- Governance is the only path to side-effecting MCP tools
- Security tooling from the PRD enabled before the first public release tag
