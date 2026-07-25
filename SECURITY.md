# Security Policy

ScamFighter handles attacker-controlled content and can produce actions and
reports. We take security seriously and appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

- Use GitHub's private vulnerability reporting ("Report a vulnerability" under the
  repository's Security tab), or
- Contact the maintainers privately as listed in `.github/CODEOWNERS`.

Please include: affected version/commit, reproduction steps, impact, and any
suggested remediation. We aim to acknowledge within a few days and to coordinate a
fix and disclosure timeline with you.

## Scope

In scope: the ScamFighter code, MCP servers, governance boundary, evidence vault,
and CI/supply-chain configuration.

Out of scope: third-party services, the operator's own mail infrastructure, and
anything requiring the operator to have misconfigured their deployment.

## Handling malicious content safely

ScamFighter never fetches URLs from scam mail, never executes or renders
attachments, and parses all input as hostile. If you find a way to make it do
otherwise, that is a security bug — please report it.

Live third-party submits (e.g. Spamhaus) require an explicit confirmation phrase
**and** `SCAMFIGHTER_ALLOW_LIVE_SUBMIT=1`. Bypassing either without a clear
operator intent is also a security bug.

## Supply-chain expectations

- Signed commits and reviewed PRs on `main`.
- Committed lockfile and pinned dependencies; Dependabot enabled.
- OSV/pip-audit/CodeQL/Semgrep/OpenSSF Scorecard run in CI.
- Secret scanning and push protection enabled.

## No hack-back

ScamFighter is defensive. Reports of "missing" offensive capabilities are not
security issues; offensive capability is intentionally absent (see
`docs/LEGAL.md`).
