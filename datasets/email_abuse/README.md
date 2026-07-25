# Email abuse training set (small-model ready)

Labeled, PII-scrubbed examples exported from local ScamFighter evidence packs
(`~/ScamFighter/packs`) plus the in-repo sextortion fixture. Intended for later
fine-tuning / distillation of a **small** classifier (not for publishing raw `.eml`).

## Regenerate

```bash
export PYTHONPATH=packages/scamfighter_core
python tools/export_training_dataset.py
# or
python tools/export_training_dataset.py --packs ~/ScamFighter/packs --out datasets/email_abuse
```

Edit `whitelist.json` to mark campaigns as `benign_noise` (same idea as the
canvas whitelist ticks for Vernimmen / LinkedIn / GitHub notifications).

## Files

| File | Role |
|------|------|
| `train.jsonl` | One JSON object per line (features + labels) |
| `manifest.json` | Counts, label histogram, export timestamp |
| `whitelist.json` | Campaign ids forced to `benign_noise` |

## Label set

| Label | Meaning |
|-------|---------|
| `sextortion` | “I RECORDED YOU” bot wave (+ fixture) |
| `phishing` | Brand / Espace Client (Sofinco-class) |
| `spam` | Generic spam (e.g. fake insurance) |
| `benign_noise` | Whitelisted newsletters / GitHub CI mail |
| `unknown` / `suspicious` | Residual detector classes if not remapped |

## Fields (per line)

- **Target:** `label`
- **Grouping:** `campaign`, `split_group`, `is_bot_wave` — keep a whole bot
  campaign in train *or* test, never both (group split).
- **Text:** `subject`, `body_text`, `from_display` (scrubbed)
- **Structure:** auth (`spf`/`dkim`/`dmarc`), `self_addressed`,
  `irregularities`, `disambiguation`, `has_bitcoin`, `url_*`, `origin_ip_count`
- **Teacher:** `detector_verdict`, `detector_confidence` (rule-based ScamFighter)

## Suggested train/eval split

```text
GroupKFold / GroupShuffleSplit on split_group
  → i_recorded_you_sextortion_bot is one group (43 near-duplicates ≠ 43 i.i.d. rows)
```

## Privacy

- Addresses → `redacted@example.com`
- Personal domain fragments masked
- Origin IPs last octet zeroed in free text
- No raw `.eml` in this folder

Do not commit unscrubbed mailbox dumps.
