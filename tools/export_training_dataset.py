#!/usr/bin/env python3
"""Export scrubbed labeled examples from local evidence packs for small-model training.

Reads ``~/ScamFighter/packs/*/meta.json`` (+ optional ``message.eml`` body text),
applies a campaign whitelist (false-positive / noise), and writes JSONL suitable
for later fine-tuning of a tiny classifier.

Observe-only: never sends mail or contacts third parties.

Usage::

    PYTHONPATH=packages/scamfighter_core python tools/export_training_dataset.py
    PYTHONPATH=packages/scamfighter_core python tools/export_training_dataset.py \\
        --packs ~/ScamFighter/packs --out datasets/email_abuse
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

# Repo root = parent of tools/
_REPO = Path(__file__).resolve().parents[1]
if str(_REPO / "packages" / "scamfighter_core") not in sys.path:
    sys.path.insert(0, str(_REPO / "packages" / "scamfighter_core"))

from scamfighter_core.email_ingest import html_to_text, parse_eml_bytes  # noqa: E402
from scamfighter_core.pipeline import analyze  # noqa: E402

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_DISPLAY_RE = re.compile(r'^"?\s*([^"<@]+?)\s*"?\s*<', re.UNICODE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Domains / locals that must never appear in committed training text.
_PII_DOMAIN_FRAGMENTS = (
    "dezard.net",
    "jeanbapt",
)


@dataclass(frozen=True)
class TrainingExample:
    """One labeled mail for supervised training / eval."""

    id: str
    label: str
    campaign: str
    is_bot_wave: bool
    whitelisted: bool
    split_group: str
    subject: str
    body_text: str
    from_display: str
    from_domain: str
    to_domain: str
    self_addressed: bool
    spf: str | None
    dkim: str | None
    dmarc: str | None
    auth_all_failing: bool
    irregularities: list[str]
    disambiguation: list[str]
    matched_phrases: list[str]
    has_bitcoin: bool
    url_count: int
    url_registrable_domains: list[str]
    origin_ip_count: int
    detector_verdict: str
    detector_confidence: float
    source_sha256_prefix: str
    exported_at: str


def _scrub_text(text: str) -> str:
    out = _EMAIL_RE.sub("redacted@example.com", text)
    for frag in _PII_DOMAIN_FRAGMENTS:
        out = re.sub(re.escape(frag), "example", out, flags=re.IGNORECASE)
    # Keep IPs as structure but zero the last octet to reduce fingerprinting.
    def _mask_ip(m: re.Match[str]) -> str:
        parts = m.group(0).split(".")
        parts[-1] = "0"
        return ".".join(parts)

    out = _IPV4_RE.sub(_mask_ip, out)
    return out


def _domain(addr: str) -> str:
    return addr.rpartition("@")[-1].lower().strip()


def _safe_domain(addr_or_domain: str) -> str:
    d = _domain(addr_or_domain) if "@" in addr_or_domain else addr_or_domain.lower().strip()
    for frag in _PII_DOMAIN_FRAGMENTS:
        if frag in d:
            return "example.com"
    return d or "unknown"


def _registrable(host: str) -> str:
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _campaign_for(subject: str, from_addr: str, case_id: str) -> tuple[str, str, bool]:
    """Return (campaign_name, label_hint, is_bot_wave)."""
    subj = subject.lower()
    for prefix in ("[spam] ", "re: ", "fwd: "):
        if subj.startswith(prefix):
            subj = subj[len(prefix) :]
    frm = from_addr.lower()

    if "recorded you" in subj:
        return "i_recorded_you_sextortion_bot", "sextortion", True
    if "espace client" in subj or "girlpowertalk" in frm or "sofinco" in frm:
        return "sofinco_espace_client_phishing", "phishing", False
    if "github.com" in frm or "noreply.github.com" in frm:
        return "github_notifications", "benign_noise", False
    if "vernimmen" in frm:
        return "vernimmen_newsletter", "benign_noise", False
    if "linkedin.com" in frm:
        return "linkedin_newsletter", "benign_noise", False
    if "coverage" in subj or "bluecross" in subj or "biuecross" in frm:
        return "health_insurance_spam", "spam", False
    if "dealexmachina" in case_id.lower() or "dealexmachina" in subject.lower():
        return "github_notifications", "benign_noise", False
    return "other", "unknown", False


def _body_from_eml(path: Path, *, max_chars: int = 2500) -> str:
    if not path.is_file() or path.stat().st_size == 0:
        return ""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    except Exception:
        return ""
    plains: list[str] = []
    htmls: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                content = str(part.get_content())
            except Exception:  # noqa: S112 — skip undecodable hostile parts
                continue
            if ctype == "text/plain":
                plains.append(content)
            elif ctype == "text/html":
                htmls.append(content)
    else:
        try:
            content = str(msg.get_content()) if msg.get_content_maintype() == "text" else ""
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            htmls.append(content)
        elif content:
            plains.append(content)
    raw = "\n".join(plains) if plains else html_to_text("\n".join(htmls))
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw[:max_chars]


def _load_whitelist(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    campaigns = data.get("campaigns") or data.get("whitelist") or []
    return {str(c) for c in campaigns}


def _example_id(sha_prefix: str, case_id: str) -> str:
    digest = hashlib.sha256(f"{case_id}:{sha_prefix}".encode()).hexdigest()[:16]
    return f"ex_{digest}"


def export_packs(
    packs_root: Path,
    *,
    whitelist: set[str],
    include_fixtures: bool,
) -> list[TrainingExample]:
    now = datetime.now(UTC).isoformat()
    examples: list[TrainingExample] = []

    dirs = sorted(p for p in packs_root.iterdir() if p.is_dir()) if packs_root.is_dir() else []
    for pack_dir in dirs:
        meta_path = pack_dir / "meta.json"
        if not meta_path.is_file():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        analysis = meta.get("analysis") or {}
        case_id = str(meta.get("case_id") or pack_dir.name)
        sha = str(meta.get("sha256") or "")
        subject = str(analysis.get("subject") or "")
        from_addr = str(analysis.get("from_addr") or "")

        campaign, label_hint, is_bot = _campaign_for(subject, from_addr, case_id)
        whitelisted = campaign in whitelist
        if whitelisted:
            label = "benign_noise"
        elif label_hint in {"sextortion", "phishing", "spam", "benign_noise"}:
            label = label_hint
        else:
            # Fall back to detector verdict when campaign is unknown.
            det = str(analysis.get("verdict") or "unknown")
            label = "benign_noise" if det == "unknown" else det

        eml_path = pack_dir / "message.eml"
        body = _scrub_text(_body_from_eml(eml_path))

        # Prefer live re-analysis when .eml is present (irregularities / disambiguation).
        irregularities = list(analysis.get("irregularities") or [])
        disambiguation = list(analysis.get("disambiguation") or [])
        matched = list(analysis.get("matched_phrases") or [])
        urls = list(analysis.get("urls_defanged") or [])
        confidence = float(analysis.get("confidence") or 0.0)
        verdict = str(analysis.get("verdict") or "unknown")
        spf = analysis.get("spf")
        dkim = analysis.get("dkim")
        dmarc = analysis.get("dmarc")
        self_addr = bool(analysis.get("is_self_addressed"))
        auth_fail = bool(analysis.get("auth_all_failing"))
        has_btc = bool(analysis.get("bitcoin_addresses"))
        origin_n = len(analysis.get("public_ips") or [])
        from_display = ""

        if eml_path.is_file() and eml_path.stat().st_size > 0:
            try:
                parsed = parse_eml_bytes(eml_path.read_bytes())
                live = analyze(parsed)
                irregularities = list(live.irregularities)
                disambiguation = list(live.disambiguation)
                matched = list(live.matched_phrases)
                urls = list(live.urls)
                confidence = live.confidence
                verdict = live.verdict
                spf, dkim, dmarc = live.spf, live.dkim, live.dmarc
                self_addr = live.is_self_addressed
                auth_fail = live.auth_all_failing
                has_btc = bool(live.bitcoin_addresses)
                origin_n = len(live.public_ips)
                from_addr = live.from_addr
                subject = live.subject
                hdr = parsed.headers.get("From") or ""
                m = _DISPLAY_RE.match(hdr.strip())
                from_display = m.group(1).strip() if m else ""
                if not body:
                    body = _scrub_text(re.sub(r"\s+", " ", parsed.body).strip()[:2500])
            except Exception:  # noqa: S110 — keep meta-only row if re-parse fails
                pass

        url_regs: list[str] = []
        for u in urls:
            cleaned = (
                u.replace("hxxp://", "http://")
                .replace("hxxps://", "https://")
                .replace("[.]", ".")
            )
            host = urlparse(cleaned).hostname or ""
            reg = _registrable(host)
            if reg and reg not in url_regs:
                url_regs.append(reg)

        examples.append(
            TrainingExample(
                id=_example_id(sha[:12], case_id),
                label=label,
                campaign=campaign,
                is_bot_wave=is_bot,
                whitelisted=whitelisted,
                split_group=campaign,
                subject=_scrub_text(subject)[:300],
                body_text=body,
                from_display=_scrub_text(from_display)[:120],
                from_domain=_safe_domain(from_addr),
                to_domain=_safe_domain(str(analysis.get("to_addr") or "")),
                self_addressed=self_addr,
                spf=str(spf) if spf is not None else None,
                dkim=str(dkim) if dkim is not None else None,
                dmarc=str(dmarc) if dmarc is not None else None,
                auth_all_failing=auth_fail,
                irregularities=irregularities,
                disambiguation=disambiguation,
                matched_phrases=matched,
                has_bitcoin=has_btc,
                url_count=len(urls),
                url_registrable_domains=url_regs[:20],
                origin_ip_count=origin_n,
                detector_verdict=verdict,
                detector_confidence=confidence,
                source_sha256_prefix=sha[:12],
                exported_at=now,
            )
        )

    if include_fixtures:
        fixture = _REPO / "tests" / "fixtures" / "i_recorded_you.eml"
        if fixture.is_file():
            parsed = parse_eml_bytes(fixture.read_bytes())
            live = analyze(parsed)
            hdr = parsed.headers.get("From") or ""
            m = _DISPLAY_RE.match(hdr.strip())
            examples.append(
                TrainingExample(
                    id="ex_fixture_i_recorded_you",
                    label="sextortion",
                    campaign="i_recorded_you_sextortion_bot",
                    is_bot_wave=True,
                    whitelisted=False,
                    split_group="i_recorded_you_sextortion_bot",
                    subject=_scrub_text(live.subject)[:300],
                    body_text=_scrub_text(re.sub(r"\s+", " ", parsed.body).strip()[:2500]),
                    from_display=(m.group(1).strip() if m else ""),
                    from_domain=_safe_domain(live.from_addr),
                    to_domain=_safe_domain(live.to_addr),
                    self_addressed=live.is_self_addressed,
                    spf=live.spf,
                    dkim=live.dkim,
                    dmarc=live.dmarc,
                    auth_all_failing=live.auth_all_failing,
                    irregularities=list(live.irregularities),
                    disambiguation=list(live.disambiguation),
                    matched_phrases=list(live.matched_phrases),
                    has_bitcoin=bool(live.bitcoin_addresses),
                    url_count=len(live.urls),
                    url_registrable_domains=[
                        _registrable(urlparse(u).hostname or "")
                        for u in live.urls
                        if urlparse(u).hostname
                    ][:20],
                    origin_ip_count=len(live.public_ips),
                    detector_verdict=live.verdict,
                    detector_confidence=live.confidence,
                    source_sha256_prefix="fixture",
                    exported_at=now,
                )
            )

    # Dedupe by id (fixture vs pack overlap).
    seen: set[str] = set()
    unique: list[TrainingExample] = []
    for ex in examples:
        if ex.id in seen:
            continue
        seen.add(ex.id)
        unique.append(ex)
    return unique


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--packs",
        type=Path,
        default=Path.home() / "ScamFighter" / "packs",
        help="Evidence packs root (default: ~/ScamFighter/packs)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_REPO / "datasets" / "email_abuse",
        help="Output directory",
    )
    parser.add_argument(
        "--whitelist",
        type=Path,
        default=_REPO / "datasets" / "email_abuse" / "whitelist.json",
        help="JSON file listing campaign ids to label benign_noise",
    )
    parser.add_argument(
        "--no-fixtures",
        action="store_true",
        help="Skip tests/fixtures seed example",
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    whitelist = _load_whitelist(args.whitelist)
    examples = export_packs(
        args.packs,
        whitelist=whitelist,
        include_fixtures=not args.no_fixtures,
    )

    jsonl_path = args.out / "train.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(asdict(ex), ensure_ascii=False) + "\n")

    labels = Counter(ex.label for ex in examples)
    campaigns = Counter(ex.campaign for ex in examples)
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "packs_root": str(args.packs),
        "example_count": len(examples),
        "labels": dict(labels),
        "campaigns": dict(campaigns),
        "whitelist": sorted(whitelist),
        "files": {
            "train_jsonl": str(jsonl_path.relative_to(_REPO))
            if jsonl_path.is_relative_to(_REPO)
            else str(jsonl_path),
            "whitelist": str(args.whitelist),
        },
        "notes": [
            "PII scrubbed (emails → redacted@example.com; personal domain fragments masked).",
            "Use split_group for group-aware train/test splits (bot waves stay together).",
            "label is the training target; detector_verdict is the rule-based teacher signal.",
        ],
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"Wrote {len(examples)} examples → {jsonl_path}")
    print("Labels:", dict(labels))
    print("Campaigns:", dict(campaigns))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
