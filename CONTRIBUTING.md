# Contributing to ScamFighter

Thank you for helping make lawful scam response accessible. Contribution is
**open**; trust is **gated**. Anyone may fork and open a pull request. Merging is
restricted to vetted maintainers with required review and checks.

## Ground rules

By contributing you agree that your work stays within ScamFighter's posture:

- **Defensive only.** No offensive/hack-back features, no harassment or automated
  engagement with scammers. See `docs/LEGAL.md`.
- **Governed side effects.** Any action that affects the world must go through the
  `Governance` boundary (`docs/GOVERNANCE.md`).
- **Privacy first.** Do not add silent cloud offload of email content; keep
  processing local by default.
- **Treat input as hostile.** No URL auto-fetch, no attachment execution; parse
  defensively. See `docs/THREAT_MODEL.md`.

## Development

```bash
cp .env.example .env
uv run --with pytest pytest -q        # tests
uv run --with ruff ruff check .       # lint
uv run --with ruff ruff format .      # format
```

Requirements:
- Python 3.13+ and `uv`.
- Typed code; strict Pydantic/YAML for data models.
- New behavior comes with tests. Side-effecting or governance changes require tests
  proving the guarantees still hold (unauthorized transition rejected; no action
  without approval).

## Pull requests

- Keep PRs focused and small where possible.
- **Sign your commits** (`git commit -S`). Signed commits are required on `main`.
- We use the Developer Certificate of Origin: sign off each commit with
  `git commit -s` (adds a `Signed-off-by` line).
- Fill in the PR description: what, why, and how it was tested.
- CI (lint, typecheck, tests) must pass; sensitive areas (governance,
  `mail-actions`, reporting) require a maintainer review via `CODEOWNERS`.

## Trust model

- Anyone: fork, PR, review, discuss.
- Maintainers: merge rights, releases, handling sensitive detection signatures.
- Detection logic whose disclosure would materially aid scammer evasion may live in
  a separate access-controlled feed rather than in this repo. Ask before adding
  such material.

## Reporting security issues

Please follow `SECURITY.md` — do not open public issues for vulnerabilities.

## Code of Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.
