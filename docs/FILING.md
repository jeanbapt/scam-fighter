# Filing abuse reports (OVH + French authorities)

ScamFighter builds **local evidence packs** (`scamfighter pack`). It does **not**
submit tickets or send mail. You review the pack, then file it yourself.

Legal posture: defensive intermediary only — see [LEGAL.md](LEGAL.md). This page
is operational guidance, not legal advice.

## Generate a pack

```bash
export PYTHONPATH=packages/scamfighter_core:apps/scamfighter

# From the watcher's processed folder (or any .eml):
uv run python -m scamfighter_app pack --path ~/ScamFighter/processed

# Defaults:
#   vault -> ~/ScamFighter/evidence/by-hash/...
#   packs -> ~/ScamFighter/packs/<case-id>/
```

Each pack contains:

| File | Purpose |
|------|---------|
| `message.eml` | Unmodified original (primary exhibit) |
| `complaint_fr.md` | French draft for THESEE / police / OVH |
| `complaint_en.md` | English draft |
| `iocs.txt` | Defanged BTC / IPs / URLs |
| `meta.json` | Analysis + SHA-256 |
| `MANIFEST.sha256` | Hashes of pack files |
| `README.md` | Index |

## OVHcloud (registrar / mail host)

Use when the mailbox or domain is hosted/registered at OVH.

1. **Abuse form** (preferred for structured tickets)  
   - FR: https://www.ovhcloud.com/fr/abuse/  
   - EN: https://www.ovhcloud.com/en/abuse/  
   - Category: **Phishing / Scam** (or **Spam** if pure bulk).  
   - Attach `message.eml` and quote the SHA-256 from `meta.json` / `complaint_*.md`.  
   - Include the origin IP(s) from the pack when reporting infrastructure abuse.

2. **fraude@ovh.com**  
   OVH documents that phishing/fraud emails can be saved as `.eml` / `.msg` and
   sent as an attachment to **fraude@ovh.com** (see OVH docs on recognising
   fraudulent emails). Useful when the scam spoofs OVH or targets OVH customers.

3. Do **not** expect OVH to “take down” an unrelated scammer IP that is not on
   their network — use the form for content/activity on OVH services, and use
   RDAP/`abuse@` of the *origin IP’s* host for other providers (future ScamFighter
   enrichment).

## French authorities (sextorsion / arnaque)

Official victim guidance (Cybermalveillance.gouv.fr):
https://www.cybermalveillance.gouv.fr/tous-nos-contenus/fiches-reflexes/sextorsion

Practical sequence:

1. **Do not pay, do not reply**, keep the original `.eml`.
2. **THESEE — plainte en ligne** for internet scams / related cybercrime:  
   - https://www.service-public.gouv.fr/particuliers/vosdroits/N31138  
   - https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/thesee-arnaques-internet-plainte-en-ligne  
   Upload / describe using `complaint_fr.md` + attach `message.eml`.
3. **Commissariat / gendarmerie**, or written complaint to the **procureur de la
   République** of your tribunal judiciaire, with the same pack.
4. Help lines:  
   - **Info Escroqueries** — 0 805 805 817 (Mon–Fri 9:00–18:30)  
   - **France Victimes** — 116 006  
   - **3018** (cyberharassment / digital violence listening line)

Qualification often discussed for webcam/sextortion blackmail: **chantage**
(Code pénal art. 312-10 et s.) — the authority decides the exact charge.

## Crypto address

Report the Bitcoin address from `iocs.txt` to crypto-abuse desks (e.g. Chainabuse)
and any exchange named only as a *payment venue* in the body — those URLs are
usually decoys, not the attacker’s host.

## What to emphasize in every filing

1. Unmodified `.eml` + SHA-256.  
2. Self-addressed From=To spoof.  
3. SPF/DKIM/DMARC all failing (debunks “I emailed you from your account”).  
4. Origin IP(s) from the `Received` chain.  
5. BTC ransom address.  
6. You did not pay / did not engage.
