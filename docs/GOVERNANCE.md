# Governance

ScamFighter can take actions that affect the world: quarantining your own mail,
filing abuse reports, notifying a registrar. Any such action must be **governed**.
Governance gives three guarantees, independent of the backend:

1. **Validated state machine** — only allowed transitions occur.
2. **Approval gate** — no side effect without a recorded approval.
3. **Tamper-evident audit trail** — append-only, hash-chained events.

## Why a boundary, not a framework dependency

Earlier drafts made an external engine ("SGRS") the load-bearing dependency of the
whole system. That is a problem for an open, hardened project:

- Contributors cannot build on or reason about an unpublished engine.
- Coupling the mission (help victims) to proving out a framework is a conflict of
  interest — the mission must always win.
- Observe-only Phase 1 has no side effects, so it needs no external engine at all.

So governance is an **interface**. Agents and MCP servers depend only on the
`Governance` Protocol. Concrete engines are adapters.

```python
from scamfighter_core import Governance, LocalGovernance

gov: Governance = LocalGovernance()  # Phase 1, stdlib only
# later:
# gov: Governance = SgrsGovernance(...)  # drop-in adapter, no caller changes
```

## The Protocol

`scamfighter_core.Governance` (see `packages/scamfighter_core/scamfighter_core/governance.py`):

- `propose_transition(Transition)` — validate + record a case state change, or raise.
- `record_approval(ApprovalDecision)` — persist an approval for later gating.
- `require_approval(case_id)` — fetch a valid approval, or raise.
- `audit_log(case_id)` — return the append-only, hash-chained trail.

## Case lifecycle

```
ingested -> analyzed -> evidenced -> planned -> approved -> executed -> closed
```

- Any state may transition to `closed`.
- Entering `executed` (the only inherently side-effecting state) **requires** a
  recorded, positive `ApprovalDecision`. This is what makes "no unapproved action"
  a structural guarantee rather than a convention.

## Audit trail

Each event is hash-chained: `this_hash = sha256(event || prev_hash)`. Any edit to a
past event breaks the chain, so tampering is detectable. Phase 1 keeps this in
memory / SQLite; a durable or externally-anchored log (transparency log, RFC 3161)
can back the same interface later.

## Adding an SGRS (or other) adapter

Implement the four `Governance` methods against the engine, keep the same
lifecycle and approval semantics, and inject it wherever `LocalGovernance` is used.
No agent, MCP server, or test should need to change.
