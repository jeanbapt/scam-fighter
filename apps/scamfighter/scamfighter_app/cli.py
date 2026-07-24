"""ScamFighter CLI: ingest mail, analyze deterministically, optionally summarize.

Observe-only. Reads mail read-only; never mutates a mailbox; only escalates to the
cloud through the guarded, ShieldFlow-protected path when explicitly asked.

Examples::

    # Recommended: read the watch folder a Mail rule exports into (no macOS
    # permission needed at all; see docs/MACOS_MAIL.md). Defaults to
    # ~/ScamFighter/inbox.
    python -m scamfighter_app ingest --source folder

    # Draft local summaries for scam hits
    python -m scamfighter_app ingest --source folder --summarize

    # Advanced: read Apple Mail's on-disk store (needs Full Disk Access)
    python -m scamfighter_app ingest --source macmail --path "~/Library/Mail/V10"
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from scamfighter_core import (
    Analysis,
    CompositeEgressGuard,
    DeterministicRedactor,
    FolderSource,
    ImapSource,
    MacMailSource,
    MailSource,
    OllamaLocalProvider,
    OpenAICompatibleProvider,
    ParsedEmail,
    ProviderRouter,
    ShieldFlowConfig,
    ShieldFlowGuard,
    analyze,
    defang,
    load_config,
    summarize,
)

DEFAULT_WATCH_FOLDER = Path.home() / "ScamFighter" / "inbox"


def build_source(args: argparse.Namespace) -> MailSource:
    if args.source == "folder":
        path = Path(os.path.expanduser(args.path)) if args.path else DEFAULT_WATCH_FOLDER
        if not path.exists():
            raise SystemExit(
                f"watch folder not found: {path}\n"
                "Create it and export mail into it, or set up the Mail rule "
                "described in docs/MACOS_MAIL.md (no Full Disk Access needed)."
            )
        return FolderSource(path)
    if args.source == "macmail":
        root = Path(os.path.expanduser(args.path)) if args.path else None
        return MacMailSource(root=root)
    if args.source == "imap":
        host = args.imap_host or os.environ.get("IMAP_HOST", "")
        user = args.imap_user or os.environ.get("IMAP_USER", "")
        password = os.environ.get("IMAP_PASSWORD", "")
        if not (host and user and password):
            raise SystemExit("IMAP requires --imap-host/--imap-user and IMAP_PASSWORD env")
        return ImapSource(host, user, password, folder=args.imap_folder)
    raise SystemExit(f"unknown source: {args.source}")


def build_router(*, escalate: bool) -> ProviderRouter:
    """Local Ollama by default; add a guarded cloud provider only if escalating."""
    local = OllamaLocalProvider(model=os.environ.get("SCAMFIGHTER_LOCAL_MODEL", "qwen2.5:3b"))
    cloud: OpenAICompatibleProvider | None = None
    if escalate:
        cfg: ShieldFlowConfig | None = load_config()
        if cfg is None:
            raise SystemExit("cloud escalation requires ShieldFlow (not found); aborting")
        guard = CompositeEgressGuard(
            [DeterministicRedactor(), ShieldFlowGuard.discover()], strict=True
        )
        api_key = os.environ.get("SCAMFIGHTER_CLOUD_API_KEY", "")
        base_url = os.environ.get("SCAMFIGHTER_CLOUD_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("SCAMFIGHTER_CLOUD_MODEL", "gpt-4o-mini")
        if not api_key:
            raise SystemExit("cloud escalation requires SCAMFIGHTER_CLOUD_API_KEY")
        cloud = OpenAICompatibleProvider(
            model, base_url=base_url, api_key=api_key, guard=guard, shieldflow=cfg
        )
    return ProviderRouter(local, cloud)


def _format(analysis: Analysis) -> str:
    tag = {"sextortion": "[SCAM]", "suspicious": "[?]", "unknown": "[ ]"}[analysis.verdict]
    lines = [
        f"{tag} {analysis.verdict} ({analysis.confidence:.2f}) | {analysis.subject}",
        (
            f"    from={analysis.from_addr} to={analysis.to_addr} "
            f"self_addressed={analysis.is_self_addressed}"
        ),
        (
            f"    auth: spf={analysis.spf} dkim={analysis.dkim} dmarc={analysis.dmarc} "
            f"(all_failing={analysis.auth_all_failing})"
        ),
    ]
    if analysis.bitcoin_addresses:
        lines.append(f"    btc: {', '.join(analysis.bitcoin_addresses)}")
    if analysis.public_ips:
        lines.append(f"    origin_ips: {', '.join(analysis.public_ips)}")
    if analysis.urls:
        lines.append(f"    urls: {', '.join(defang(u) for u in analysis.urls)}")
    return "\n".join(lines)


def run_ingest(args: argparse.Namespace, *, out=sys.stdout) -> int:
    source = build_source(args)
    router = build_router(escalate=args.escalate) if args.summarize else None

    parsed_iter: Iterator[ParsedEmail] = source.iter_parsed(limit=args.limit)
    total = scams = 0
    for parsed in parsed_iter:
        total += 1
        analysis = analyze(parsed)
        if analysis.is_sextortion:
            scams += 1
        if analysis.verdict == "unknown" and not args.all:
            continue
        print(_format(analysis), file=out)
        if router is not None and analysis.verdict != "unknown":
            summary = summarize(parsed, router, escalate=args.escalate)
            print(f"    summary: {summary}", file=out)
    print(f"\nProcessed {total} message(s); {scams} sextortion hit(s).", file=out)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scamfighter", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="ingest and analyze mail (observe-only)")
    ingest.add_argument(
        "--source",
        choices=["folder", "macmail", "imap"],
        default="folder",
        help="folder (least privilege, default), macmail (needs Full Disk Access), or imap",
    )
    ingest.add_argument(
        "--path",
        help="folder of .eml/.emlx (folder; default ~/ScamFighter/inbox) "
        "or mailbox root e.g. ~/Library/Mail/V10 (macmail)",
    )
    ingest.add_argument("--limit", type=int, default=50)
    ingest.add_argument("--all", action="store_true", help="show non-scam messages too")
    ingest.add_argument("--summarize", action="store_true", help="draft LLM summaries")
    ingest.add_argument(
        "--escalate",
        action="store_true",
        help="use guarded cloud LLM (through ShieldFlow) instead of local",
    )
    ingest.add_argument("--imap-host")
    ingest.add_argument("--imap-user")
    ingest.add_argument("--imap-folder", default="INBOX")
    ingest.set_defaults(func=run_ingest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
