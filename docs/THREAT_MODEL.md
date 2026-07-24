# Threat model

ScamFighter ingests attacker-controlled content and can produce actions and
reports. It must be hardened as both a **malware-handling tool** and a
**supply-chain target**.

## Assets to protect

- Victim and third-party PII contained in scam mail.
- Integrity of the evidence vault (must be trustworthy to authorities).
- The operator's mailbox and machine.
- The integrity of the codebase and its releases.

## Adversaries

1. **The scammer**, whose content we parse. Assume every field is hostile.
2. **A malicious "contributor"**, attempting a supply-chain attack via PR.
3. **An opportunistic attacker** targeting operator deployments.

## Threats and mitigations

### Handling live malicious content
- **No URL auto-fetch.** Links are extracted and defanged (`hxxp://`), never
  requested.
- **No attachment execution or rendering.** Attachments are hashed and stored, not
  opened.
- **Sandboxed, hostile-input parsing.** Treat headers, MIME, encodings as
  untrusted; parsers are fuzzed; fail closed.
- **Injection resistance.** LLM inputs are scam text; use fixed typed tool schemas
  (no model-authored code execution) to blunt prompt-injection into actions.
- **Guarded cloud egress.** Cloud LLM calls route through the LiquidAI ShieldFlow
  local proxy (tokenizes PII in transit, blocks prompt injection) and are gated by
  the fail-closed egress guard (`scamfighter_core.egress_guard` +
  `scamfighter_core.shieldflow`). If ShieldFlow is not active, or a semantic guard
  cannot vouch for the text, it is not sent. Deterministic in-process redaction is
  an independent second layer.
- **ShieldFlow trust material stays out of the repo.** Its CA bundle, control
  token, and proxy config live under `~/.shieldflow/` and are never committed.

### Least-privilege mail access
- Default to `--source folder`: the operator exports only suspect messages, so the
  tool sees nothing else on disk and needs no macOS permission.
- Recommended Apple Mail on-ramp is a **Mail rule -> AppleScript** that exports
  matched messages into the watch folder. It runs inside Mail, so it needs neither
  Full Disk Access nor an Automation prompt, and only ever touches rule-matched
  mail (`tools/macos/scamfighter-mail-rule.applescript`).
- macOS **Full Disk Access is coarse** — TCC grants it to the responsible app (the
  terminal/IDE), exposing all protected data to any code that app runs, including
  dependencies. Treat FDA-to-terminal as a supply-chain amplifier; if the raw
  `.emlx` store is required, grant FDA to a minimal signed helper only.
- IMAP access is read-only and credentialled via Keychain/app password, scoped to
  one mailbox.

### Preventing unsafe actions
- Observe-only by default; `mail-actions` disabled unless mode + governance allow.
- Every side effect requires a governed transition + recorded approval
  (`docs/GOVERNANCE.md`).
- Action tools operate only on the operator's own mailbox/resources.

### Protecting evidence integrity
- Write-once vault; SHA-256 content addressing; hash-chained audit log.
- Trusted timestamps (RFC 3161) or transparency-log anchoring.

### Supply-chain / repo integrity
- Signed commits; branch protection; required reviews; `CODEOWNERS` on sensitive
  areas (governance, `mail-actions`, reporting).
- Committed lockfile; pinned dependencies; Dependabot.
- OSV Scanner, pip-audit, CodeQL, Semgrep, gitleaks, dependency-review, and
  OpenSSF Scorecard in CI (SHA-pinned Actions).
- Least-privilege `GITHUB_TOKEN`; secret scanning + push protection.
- SBOM + Sigstore provenance on releases (deferred to first public tag).
- Optional local parity via `.pre-commit-config.yaml` (ruff + gitleaks).

### Detection-evasion risk
- Publishing detection logic can help scammers evade. Keep the project open, but
  any signatures whose disclosure materially aids evasion belong in a separate,
  access-controlled feed — not gated behind closing the whole repo.

## Out of scope (Phase 1)

Multi-tenant isolation, SSO, and hardened production deployment are Phase 5.
