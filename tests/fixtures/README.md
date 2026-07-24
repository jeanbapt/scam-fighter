# Test fixtures

Sanitized, defanged sample messages safe to commit and use in tests.

## Rules

- **Never commit real captured mail here.** Real `.eml`/`.msg` samples contain
  recipient PII and live attacker content; they belong in the git-ignored
  `samples/` directory at the repo root (see `.gitignore`).
- Fixtures must be sanitized before landing:
  - Replace real recipient/sender identities with `example.com` addresses.
  - Trim large opaque blobs (e.g. base64 spam-cause headers) to short placeholders.
  - Keep genuine public indicators (origin IPs, crypto addresses) only when they
    are useful test targets and are not personal data.
- Preserve realistic headers (Received chain, Authentication-Results) so parser
  tests exercise real-world structure.

## Files

- `i_recorded_you.eml` — sanitized "I RECORDED YOU!" sextortion sample. Self-
  addressed spoof (`From` == `To`), `spf=softfail`, `dkim=none`, `dmarc=fail`.
  Derived from a real message stored locally under `samples/` (not committed).
