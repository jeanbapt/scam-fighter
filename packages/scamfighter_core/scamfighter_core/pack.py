"""Evidence pack builder: vault object + FR/EN complaint drafts + defanged IOCs.

Observe-only: builds files on disk for the operator to submit. Does not send mail
or open tickets. Filing channels are documented in ``docs/FILING.md``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scamfighter_core.email_ingest import ParsedEmail, defang, parse_eml_bytes
from scamfighter_core.mail_source import read_message_file
from scamfighter_core.pipeline import Analysis, analyze
from scamfighter_core.provenance import (
    ProvenanceReport,
    enrich,
    format_provenance_markdown,
)
from scamfighter_core.vault import EvidenceVault, VaultObject


@dataclass(frozen=True)
class EvidencePack:
    """Paths produced for one case."""

    case_id: str
    directory: Path
    sha256: str
    analysis: Analysis
    files: tuple[Path, ...]


def _mask_email(addr: str) -> str:
    if "@" not in addr:
        return addr
    local, _, domain = addr.partition("@")
    if len(local) <= 2:
        return f"*@{domain}"
    return f"{local[0]}...{local[-1]}@{domain}"


def _case_id(sha256: str, parsed: ParsedEmail) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    mid = parsed.message_id.strip("<>") or sha256[:12]
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in mid)[:48]
    return f"{stamp}-{safe}-{sha256[:8]}"


def _complaint_fr(
    *,
    parsed: ParsedEmail,
    analysis: Analysis,
    sha256: str,
    case_id: str,
) -> str:
    btc = ", ".join(analysis.bitcoin_addresses) or "(aucun)"
    ips = ", ".join(analysis.public_ips) or "(aucun)"
    urls = ", ".join(defang(u) for u in analysis.urls) or "(aucune)"
    return f"""# Plainte / signalement - chantage sextorsion par e-mail

**Référence dossier ScamFighter :** `{case_id}`  
**Date de constitution du pack :** {datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}  
**Empreinte SHA-256 du message original (`.eml`) :** `{sha256}`

> Document généré localement pour faciliter un dépôt de plainte ou un signalement.
> Ce n'est **pas** un envoi automatique. Vérifiez les faits avant toute démarche.

## Nature des faits

Tentative de **chantage / sextorsion** par e-mail (menace de diffusion d'enregistrements
intimes et demande de paiement en cryptomonnaie). Aucun paiement n'est recommandé ;
ne pas répondre à l'expéditeur.

Qualification possible (à l'appréciation des autorités) : **chantage**
(articles 312-10 et suivants du Code pénal).

## Éléments techniques vérifiables

| Élément | Valeur |
|--------|--------|
| Objet | {analysis.subject} |
| Date (en-tête) | {parsed.date} |
| Message-ID | {parsed.message_id} |
| From | `{analysis.from_addr}` |
| To | `{analysis.to_addr}` |
| Spoof « From = To » | {"oui" if analysis.is_self_addressed else "non"} |
| SPF | {analysis.spf} |
| DKIM | {analysis.dkim} |
| DMARC | {analysis.dmarc} |
| Auth. globalement en échec | {"oui" if analysis.auth_all_failing else "non"} |
| Adresse(s) Bitcoin | `{btc}` |
| IP d'origine (chaîne Received) | `{ips}` |
| URL mentionnées (défanguées) | {urls} |
| Verdict analyse | {analysis.verdict} (confiance {analysis.confidence}) |

**Point clé :** l'affirmation « je vous ai écrit depuis votre propre compte » est
**contredite** par les résultats d'authentification (SPF/DKIM/DMARC).

## Pièces jointes du pack

- `message.eml` - message original intact (à fournir en priorité)
- `meta.json` - métadonnées vault + analyse
- `iocs.txt` - indicateurs défangués
- `MANIFEST.sha256` - empreintes des fichiers du pack

## Où déposer / signaler (France)

1. **Plainte en ligne THESEE** (arnaques / escroqueries Internet) :
   https://www.service-public.gouv.fr/particuliers/vosdroits/N31138  
   ou https://www.masecurite.interieur.gouv.fr/fr/demarches-en-ligne/thesee-arnaques-internet-plainte-en-ligne
2. **Commissariat / gendarmerie** ou plainte écrite au procureur de la République.
3. **Conseils sextorsion** (Cybermalveillance.gouv.fr) :
   https://www.cybermalveillance.gouv.fr/tous-nos-contenus/fiches-reflexes/sextorsion
4. **Info Escroqueries** : 0 805 805 817 (lun-ven 9h-18h30).
5. **France Victimes** : 116 006.

## Hébergeur / registrar messagerie (OVHcloud)

Si le domaine ou la boîte est chez OVH :

- Formulaire Abuse (catégorie *Phishing / Scam* ou *Spam*) :
  https://www.ovhcloud.com/fr/abuse/  
  (EN : https://www.ovhcloud.com/en/abuse/)
- Pour un e-mail de phishing/fraude OVH : joindre le `.eml` à **fraude@ovh.com**
  (doc OVH « Phishing - How to recognise fraudulent emails »).

Joindre : `message.eml`, cette fiche, et l'empreinte SHA-256.

## Déclaration

Je n'ai pas payé / je n'ai pas répondu (à compléter) : _______________  
Je confirme que le fichier `message.eml` joint est l'original reçu : _______________
"""


def _complaint_en(
    *,
    parsed: ParsedEmail,
    analysis: Analysis,
    sha256: str,
    case_id: str,
) -> str:
    btc = ", ".join(analysis.bitcoin_addresses) or "(none)"
    ips = ", ".join(analysis.public_ips) or "(none)"
    urls = ", ".join(defang(u) for u in analysis.urls) or "(none)"
    return f"""# Complaint / abuse report - email sextortion scam

**ScamFighter case id:** `{case_id}`  
**Pack generated (UTC):** {datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")}  
**SHA-256 of original `.eml`:** `{sha256}`

> Generated locally to help you file a report. **Nothing is submitted automatically.**
> Verify facts before filing.

## Nature of the offence

Attempted **sextortion / blackmail** by email (threat to release intimate recordings
and a cryptocurrency ransom demand). Do not pay; do not reply.

## Verifiable technical facts

| Field | Value |
|-------|--------|
| Subject | {analysis.subject} |
| Date header | {parsed.date} |
| Message-ID | {parsed.message_id} |
| From | `{analysis.from_addr}` |
| To | `{analysis.to_addr}` |
| Self-addressed spoof (From = To) | {"yes" if analysis.is_self_addressed else "no"} |
| SPF | {analysis.spf} |
| DKIM | {analysis.dkim} |
| DMARC | {analysis.dmarc} |
| Auth all failing | {"yes" if analysis.auth_all_failing else "no"} |
| Bitcoin address(es) | `{btc}` |
| Origin IP(s) from Received | `{ips}` |
| URLs mentioned (defanged) | {urls} |
| Analysis verdict | {analysis.verdict} (confidence {analysis.confidence}) |

**Key point:** the claim “I sent this from your own account” is **debunked** by
failed SPF/DKIM/DMARC authentication.

## Pack contents

- `message.eml` - unmodified original (primary exhibit)
- `meta.json` - vault metadata + analysis
- `iocs.txt` - defanged indicators
- `MANIFEST.sha256` - hashes of pack files

## Where to file (France-focused; adapt if abroad)

1. **THESEE** online complaint (internet scams):  
   https://www.service-public.gouv.fr/particuliers/vosdroits/N31138
2. Local police / gendarmerie, or written complaint to the public prosecutor.
3. Sextortion guidance:  
   https://www.cybermalveillance.gouv.fr/tous-nos-contenus/fiches-reflexes/sextorsion
4. Crypto address: report to Chainabuse / exchange abuse desks if applicable.

## Mail host / registrar (OVHcloud)

- Abuse form (*Phishing / Scam* or *Spam*): https://www.ovhcloud.com/en/abuse/
- OVH phishing tip-line: attach the `.eml` to **fraude@ovh.com**

Attach `message.eml`, this sheet, and the SHA-256 digest.

## Statement

I did not pay / did not reply (complete): _______________  
I confirm `message.eml` is the original message I received: _______________
"""


def _iocs_text(analysis: Analysis, parsed: ParsedEmail, sha256: str) -> str:
    lines = [
        f"# Defanged IOCs - sha256={sha256}",
        f"message_id={parsed.message_id}",
        f"verdict={analysis.verdict}",
        "",
        "# Bitcoin",
        *[f"btc={a}" for a in analysis.bitcoin_addresses],
        "",
        "# Origin IPs (from Received)",
        *[f"ip={ip}" for ip in analysis.public_ips],
        "",
        "# URLs (defanged)",
        *[f"url={defang(u)}" for u in analysis.urls],
        "",
    ]
    return "\n".join(lines)


def _write_manifest(pack_dir: Path) -> Path:
    lines: list[str] = []
    for path in sorted(pack_dir.iterdir()):
        if path.name == "MANIFEST.sha256" or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    out = pack_dir / "MANIFEST.sha256"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def _message_id_domain(message_id: str) -> str | None:
    mid = message_id.strip().strip("<>")
    if "@" not in mid:
        return None
    return mid.rsplit("@", 1)[-1].lower()


def _connecting_ip(parsed: ParsedEmail) -> str | None:
    """SMTP client-ip as seen by the receiving MX (SPF / Auth-Results)."""
    for key in ("Received-SPF", "Authentication-Results"):
        raw = parsed.headers.get(key) or ""
        m = re.search(r"client-ip=([0-9.]+)", raw, re.IGNORECASE)
        if m:
            return m.group(1)
    if parsed.indicators.public_ips:
        return parsed.indicators.public_ips[0]
    return None


def build_pack(
    eml_path: Path,
    *,
    vault: EvidenceVault,
    packs_root: Path,
    enrich_provenance: bool = True,
) -> EvidencePack:
    """Analyse an ``.eml``, store it in the vault, and write a FR/EN complaint pack."""
    raw = read_message_file(eml_path)
    obj: VaultObject = vault.put_eml(raw, source_name=eml_path.name)
    parsed = parse_eml_bytes(raw)
    analysis = analyze(parsed)
    case_id = _case_id(obj.sha256, parsed)
    pack_dir = packs_root / case_id
    pack_dir.mkdir(parents=True, exist_ok=True)

    msg_dest = pack_dir / "message.eml"
    if not msg_dest.exists():
        shutil.copy2(obj.path, msg_dest)

    provenance: ProvenanceReport | None = None
    connecting = _connecting_ip(parsed)
    if enrich_provenance:
        mid_domain = _message_id_domain(parsed.message_id)
        provenance = enrich(
            ips=list(analysis.public_ips),
            domains=[mid_domain] if mid_domain else [],
            bitcoin=list(analysis.bitcoin_addresses),
            connecting_ip=connecting,
        )
        (pack_dir / "provenance.json").write_text(
            json.dumps(provenance.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (pack_dir / "provenance_en.md").write_text(
            format_provenance_markdown(provenance, lang="en"), encoding="utf-8"
        )
        (pack_dir / "provenance_fr.md").write_text(
            format_provenance_markdown(provenance, lang="fr"), encoding="utf-8"
        )

    meta = {
        "case_id": case_id,
        "sha256": obj.sha256,
        "source_path": str(eml_path),
        "vault_path": str(obj.path),
        "stored_at": obj.stored_at,
        "already_in_vault": obj.already_present,
        "connecting_ip": connecting,
        "analysis": {
            "verdict": analysis.verdict,
            "confidence": analysis.confidence,
            "subject": analysis.subject,
            "from_addr": analysis.from_addr,
            "to_addr": analysis.to_addr,
            "is_self_addressed": analysis.is_self_addressed,
            "spf": analysis.spf,
            "dkim": analysis.dkim,
            "dmarc": analysis.dmarc,
            "auth_all_failing": analysis.auth_all_failing,
            "bitcoin_addresses": list(analysis.bitcoin_addresses),
            "public_ips": list(analysis.public_ips),
            "urls_defanged": [defang(u) for u in analysis.urls],
            "matched_phrases": list(analysis.matched_phrases),
        },
        "from_masked": _mask_email(analysis.from_addr),
        "generated_at": datetime.now(UTC).isoformat(),
        "provenance_notes": list(provenance.notes) if provenance else [],
    }
    (pack_dir / "meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (pack_dir / "complaint_fr.md").write_text(
        _complaint_fr(parsed=parsed, analysis=analysis, sha256=obj.sha256, case_id=case_id),
        encoding="utf-8",
    )
    (pack_dir / "complaint_en.md").write_text(
        _complaint_en(parsed=parsed, analysis=analysis, sha256=obj.sha256, case_id=case_id),
        encoding="utf-8",
    )
    (pack_dir / "iocs.txt").write_text(_iocs_text(analysis, parsed, obj.sha256), encoding="utf-8")
    readme = f"""# Evidence pack `{case_id}`

- FR complaint draft: `complaint_fr.md`
- EN complaint draft: `complaint_en.md`
- Provenance (RDAP/DNS/BTC): `provenance_en.md` / `provenance_fr.md` / `provenance.json`
- Original message: `message.eml` (SHA-256 `{obj.sha256}`)
- IOCs: `iocs.txt`
- Filing guide: see repo `docs/FILING.md` (OVH abuse + THESEE / French authorities)

Observe-only: submit these files yourself; ScamFighter does not contact third parties.
"""
    (pack_dir / "README.md").write_text(readme, encoding="utf-8")
    _write_manifest(pack_dir)
    files = tuple(sorted(p for p in pack_dir.iterdir() if p.is_file()))
    return EvidencePack(
        case_id=case_id,
        directory=pack_dir,
        sha256=obj.sha256,
        analysis=analysis,
        files=files,
    )
