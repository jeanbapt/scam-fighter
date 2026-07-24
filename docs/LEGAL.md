# Legal basis and boundaries

> This document explains the design constraints that keep ScamFighter lawful. It
> is engineering guidance, not legal advice. Operators are responsible for
> compliance in their own jurisdiction; consult a lawyer for your situation.

ScamFighter is a **defensive intermediary**. Its purpose is to help legitimate
parties (email/hosting providers, registrars, CERTs, law enforcement) act within
their own authority. It never exerts force on the attacker directly.

## What is lawful (and is the whole product)

- Receiving, retaining, and analyzing scams sent **to you or your users**.
- Verifying sender authenticity (SPF/DKIM/DMARC) and enriching from **public**
  records (RDAP/WHOIS, passive DNS, public blocklists).
- Reporting abuse to the proper parties: your email provider, the sending
  domain's/host's `abuse@` (via RDAP), registrars, national CERTs, law enforcement
  (e.g. US IC3/FBI, UK Action Fraud, EU national police / Europol), crypto-abuse
  databases, and anti-phishing feeds (APWG, PhishTank, Google Safe Browsing,
  Spamhaus/SpamCop).
- Producing a chain-of-custody evidence package for those parties.

## What is prohibited by design

These must be **architecturally impossible**, not merely discouraged:

- **Hack-back / unauthorized access.** No probing, scanning, credential use, or
  exploitation of scammer infrastructure. Prohibited under the US CFAA, the UK
  Computer Misuse Act, and equivalent laws worldwide. The MCP tool surface simply
  does not expose any offensive capability.
- **Harassment / scam-baiting at scale.** No automated flooding or engagement.
  It can constitute harassment or unauthorized access and destroys evidentiary
  value.
- **Unlawful data processing.** Scam emails contain personal data (the victim's,
  and often third parties' from breach dumps). Under GDPR and similar regimes you
  need a lawful basis, data minimization, and retention limits.
- **Public naming-and-shaming.** Reports go to authorities/intermediaries, not
  public pillories, to avoid defamation exposure.

## Privacy / data protection

- **Local by default.** Email content is processed on-device with edge models.
- **No silent cloud offload.** Cloud LLM escalation is opt-in per case; it moves
  PII off-device and must be a deliberate operator choice. Every cloud-bound string
  passes through the fail-closed **egress guard** (`scamfighter_core.egress_guard`),
  which redacts PII on-device before anything leaves the machine (LiquidAI
  ShieldFlow as the semantic guard, plus deterministic redaction).
- **Minimize and retain deliberately.** Store what evidence requires, with a
  documented retention policy; support redaction of third-party PII in outbound
  reports where it is not needed by the recipient.
- **Vault is append-only.** Evidence integrity and deletion policy are explicit.

## Why fighting back this way is legitimate

Extortion / sextortion is a crime (blackmail/extortion). Victims and their agents
are entitled to preserve evidence and report it. The durable, defensible posture is
to make those reports **credible and actionable** — correct recipient, standard
format, verifiable chain of custody — so providers, registrars, and police can use
their own lawful powers to disrupt the campaign.

## Design test for any new feature

Ask: *"Does this help a legitimate party act within their own authority?"*
- Yes -> in scope.
- It exerts force on the attacker directly -> out of scope.
