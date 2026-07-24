## What

<!-- What does this change do? -->

## Why

<!-- Why is it needed? Link issues. -->

## How it was tested

<!-- Commands run, fixtures, edge cases. -->

## Posture checklist

- [ ] Defensive only (no offensive/hack-back, no harassment) — see `docs/LEGAL.md`
- [ ] Any side effect goes through the `Governance` boundary — see `docs/GOVERNANCE.md`
- [ ] No silent cloud offload of email content (local-first preserved)
- [ ] Ingested content treated as hostile (no URL fetch / attachment execution)
- [ ] Tests added/updated; `ruff` + `pytest` pass locally
- [ ] Commits are signed (`-S`) and signed off (`-s`)
