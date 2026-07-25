# Contributing to ScamFighter

Thank you for helping make lawful scam response accessible. Contribution is
**open**; merge trust is **gated**. Anyone may fork and open a pull request.
Merging is restricted to maintainers with required review and green CI.

## Ground rules

By contributing you agree that your work stays within ScamFighter’s posture:

- **Defensive only.** No offensive / hack-back features, no harassment or automated
  engagement with scammers. See [`docs/LEGAL.md`](docs/LEGAL.md).
- **Governed side effects.** Anything that contacts the outside world (cloud LLM,
  live Spamhaus submit, mailbox mutations) must stay behind explicit gates
  (`docs/GOVERNANCE.md`, confirm phrases, env opt-ins).
- **Privacy first.** Do not add silent cloud offload of email content; keep
  processing local by default.
- **Treat input as hostile.** No URL auto-fetch from message bodies, no attachment
  execution; parse defensively. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
- **No real PII in the repo.** Real `.eml` samples and vault contents stay under
  `~/ScamFighter/` (gitignored). Only sanitized fixtures under `tests/fixtures/`.

## Development

```bash
cp .env.example .env
export PYTHONPATH=packages/scamfighter_core:apps/scamfighter

uv run --with pytest pytest -q
uv run --with ruff ruff check packages apps tests mcp_servers/filing
uv run --with ruff ruff format packages apps tests mcp_servers/filing
uv run --with mypy mypy packages/scamfighter_core/scamfighter_core apps/scamfighter/scamfighter_app
```

Requirements:

- Python **3.13+** and [`uv`](https://github.com/astral-sh/uv).
- Typed code; keep ruff / mypy clean on touched paths.
- New behavior ships with tests. Governance, vault, and filing confirm-gate changes
  need tests that the unsafe path still fails closed.

## Pull requests

- Keep PRs focused.
- **Sign commits** (`git commit -S`) — required on `main`.
- **DCO**: `git commit -s` (adds `Signed-off-by`).
- Describe what / why / how tested in the PR body (template under `.github/`).
- CI must pass (lint, types, tests, supply-chain scanners). Sensitive areas
  (governance, mail-actions, reporting, filing submit) need maintainer review
  via [`CODEOWNERS`](.github/CODEOWNERS).

## Trust model

- Anyone: fork, PR, review, discuss.
- Maintainers: merge, releases, handling sensitive detection signatures.
- Detection logic whose disclosure would materially aid scammer evasion may live
  in a separate access-controlled feed. Ask before adding such material.

## Security issues

Follow [`SECURITY.md`](SECURITY.md) — do **not** open public issues for vulnerabilities.

## Code of Conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
