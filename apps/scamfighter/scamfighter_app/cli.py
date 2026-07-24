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

    # Hands-off: watch the folder your Mail rule exports into, analyzing new
    # drops as they arrive (Ctrl-C to stop).
    python -m scamfighter_app watch
"""

from __future__ import annotations

import argparse
import os
import sys
import time
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
    parse_eml_bytes,
    read_message_file,
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


def build_router(*, escalate: bool, audit_out=None) -> ProviderRouter:
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

        def _audit(record: dict) -> None:
            # Labels only — never print the inspected text.
            findings = ",".join(str(f) for f in record.get("findings", [])) or "-"
            line = (
                f"[egress] allowed={record.get('allowed')} "
                f"findings={findings} "
                f"semantic={record.get('semantic_pii_checked')} "
                f"injection={record.get('injection_detected')}"
            )
            print(line, file=audit_out or sys.stderr)

        cloud = OpenAICompatibleProvider(
            model,
            base_url=base_url,
            api_key=api_key,
            guard=guard,
            shieldflow=cfg,
            audit=_audit,
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


def _report(
    parsed: ParsedEmail,
    *,
    router: ProviderRouter | None,
    escalate: bool,
    show_all: bool,
    out,
    prefix: str = "",
) -> bool:
    """Analyze one message, print it if noteworthy, return whether it was sextortion.

    Any unexpected exception is caught by the caller; this helper itself only
    fails on programming errors.
    """
    analysis = analyze(parsed)
    if analysis.verdict != "unknown" or show_all:
        if prefix:
            print(prefix, file=out)
        print(_format(analysis), file=out)
        if router is not None and analysis.verdict != "unknown":
            try:
                summary = summarize(parsed, router, escalate=escalate)
                print(f"    summary: {summary}", file=out)
            except Exception as exc:  # noqa: BLE001 — never kill the loop for a summary
                print(f"    summary: [failed: {exc}]", file=out)
    return analysis.is_sextortion


def run_ingest(args: argparse.Namespace, *, out=sys.stdout) -> int:
    source = build_source(args)
    router = build_router(escalate=args.escalate, audit_out=out) if args.summarize else None

    parsed_iter: Iterator[ParsedEmail] = source.iter_parsed(limit=args.limit)
    total = scams = errors = 0
    for parsed in parsed_iter:
        total += 1
        try:
            if _report(parsed, router=router, escalate=args.escalate, show_all=args.all, out=out):
                scams += 1
        except Exception as exc:  # noqa: BLE001 — poison message must not abort the batch
            errors += 1
            print(f"[error] skipped message: {exc}", file=out)
    suffix = f" ({errors} error(s))." if errors else "."
    print(f"\nProcessed {total} message(s); {scams} sextortion hit(s){suffix}", file=out)
    return 0


def run_watch(
    args: argparse.Namespace,
    *,
    out=sys.stdout,
    _sleep=time.sleep,
    _max_iterations: int | None = None,
) -> int:
    """Tail a watch folder and analyze new .eml/.emlx drops in real time.

    Dependency-free: polls every ``--interval`` seconds and waits for a file's size
    to stop changing before reading it, so partially written exports are skipped
    until complete. A single poison/oversized message is logged and skipped — it
    never kills the watcher. Stop with Ctrl-C.
    """
    folder = Path(os.path.expanduser(args.path)) if args.path else DEFAULT_WATCH_FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    router = build_router(escalate=args.escalate, audit_out=out) if args.summarize else None

    print(f"Watching {folder} (Ctrl-C to stop)...", file=out)
    out.flush()

    processed: set[Path] = set()
    pending_size: dict[Path, int] = {}
    total = scams = errors = 0
    iterations = 0
    try:
        while True:
            for path in FolderSource(folder).iter_message_paths():
                if path in processed:
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if pending_size.get(path) != size:
                    pending_size[path] = size  # not yet stable; check again next tick
                    continue
                try:
                    parsed = parse_eml_bytes(read_message_file(path))
                    total += 1
                    stamp = time.strftime("%H:%M:%S")
                    if _report(
                        parsed,
                        router=router,
                        escalate=args.escalate,
                        show_all=args.all,
                        out=out,
                        prefix=f"[{stamp}] {path.name}",
                    ):
                        scams += 1
                except Exception as exc:  # noqa: BLE001 — poison must not kill the watcher
                    errors += 1
                    stamp = time.strftime("%H:%M:%S")
                    print(f"[{stamp}] {path.name}: skipped ({exc})", file=out)
                out.flush()
                processed.add(path)
                pending_size.pop(path, None)
            iterations += 1
            if _max_iterations is not None and iterations >= _max_iterations:
                break
            _sleep(args.interval)
    except KeyboardInterrupt:
        print(file=out)
    suffix = f" ({errors} error(s))." if errors else "."
    print(
        f"Watched {folder}: processed {total} message(s); {scams} sextortion hit(s){suffix}",
        file=out,
    )
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

    watch = sub.add_parser(
        "watch",
        help="tail the watch folder and analyze new drops in real time (observe-only)",
    )
    watch.add_argument(
        "--path",
        help="folder to watch (default ~/ScamFighter/inbox); created if missing",
    )
    watch.add_argument(
        "--interval", type=float, default=2.0, help="poll interval in seconds (default 2)"
    )
    watch.add_argument("--all", action="store_true", help="show non-scam messages too")
    watch.add_argument("--summarize", action="store_true", help="draft LLM summaries")
    watch.add_argument(
        "--escalate",
        action="store_true",
        help="use guarded cloud LLM (through ShieldFlow) instead of local",
    )
    watch.set_defaults(func=run_watch)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
