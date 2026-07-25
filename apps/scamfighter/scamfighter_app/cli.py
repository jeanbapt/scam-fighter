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
    # drops as they arrive (Ctrl-C to stop). Optionally relocate processed files.
    python -m scamfighter_app watch --move-processed
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TextIO

from scamfighter_core import (
    Analysis,
    CompositeEgressGuard,
    DeterministicRedactor,
    EvidenceVault,
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
    build_pack,
    defang,
    load_config,
    parse_eml_bytes,
    read_message_file,
    summarize,
)

DEFAULT_WATCH_FOLDER = Path.home() / "ScamFighter" / "inbox"
DEFAULT_PROCESSED_FOLDER = Path.home() / "ScamFighter" / "processed"
DEFAULT_VAULT = Path.home() / "ScamFighter" / "evidence"
DEFAULT_PACKS = Path.home() / "ScamFighter" / "packs"


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


def build_router(*, escalate: bool, audit_out: TextIO | None = None) -> ProviderRouter:
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

        def _audit(record: dict[str, object]) -> None:
            # Labels only — never print the inspected text.
            raw_findings = record.get("findings", [])
            findings_list = raw_findings if isinstance(raw_findings, list) else []
            findings = ",".join(str(f) for f in findings_list) or "-"
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
    out: TextIO,
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
            except Exception as exc:
                print(f"    summary: [failed: {exc}]", file=out)
    return analysis.is_sextortion


def _resolve_move_processed(args: argparse.Namespace) -> Path | None:
    """Return destination dir when ``--move-processed`` is set, else None."""
    value = getattr(args, "move_processed", None)
    if value is None:
        return None
    return Path(os.path.expanduser(str(value)))


def _move_processed(path: Path, dest_dir: Path) -> Path:
    """Move ``path`` into ``dest_dir``, disambiguating name collisions."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / path.name
    if target.exists():
        stem, suffix = path.stem, path.suffix
        n = 1
        while True:
            candidate = dest_dir / f"{stem}-{n}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            n += 1
    return Path(shutil.move(str(path), str(target)))


def run_ingest(args: argparse.Namespace, *, out: TextIO = sys.stdout) -> int:
    source = build_source(args)
    router = build_router(escalate=args.escalate, audit_out=out) if args.summarize else None

    parsed_iter: Iterator[ParsedEmail] = source.iter_parsed(limit=args.limit)
    total = scams = errors = 0
    for parsed in parsed_iter:
        total += 1
        try:
            if _report(parsed, router=router, escalate=args.escalate, show_all=args.all, out=out):
                scams += 1
        except Exception as exc:
            errors += 1
            print(f"[error] skipped message: {exc}", file=out)
    suffix = f" ({errors} error(s))." if errors else "."
    print(f"\nProcessed {total} message(s); {scams} sextortion hit(s){suffix}", file=out)
    return 0


def run_watch(
    args: argparse.Namespace,
    *,
    out: TextIO = sys.stdout,
    _sleep: Callable[[float], None] = time.sleep,
    _max_iterations: int | None = None,
) -> int:
    """Tail a watch folder and analyze new .eml/.emlx drops in real time.

    Dependency-free: polls every ``--interval`` seconds and waits for a file's size
    to stop changing before reading it, so partially written exports are skipped
    until complete. A single poison/oversized message is logged and skipped — it
    never kills the watcher. Stop with Ctrl-C.

    With ``--pack`` (default on), each successfully read message is also vaulted and
    written as an evidence pack before optional relocate.
    """
    folder = Path(os.path.expanduser(args.path)) if args.path else DEFAULT_WATCH_FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    router = build_router(escalate=args.escalate, audit_out=out) if args.summarize else None
    move_to = _resolve_move_processed(args)
    do_pack = bool(getattr(args, "pack", True))
    vault_root = Path(os.path.expanduser(getattr(args, "vault", str(DEFAULT_VAULT))))
    packs_root = Path(os.path.expanduser(getattr(args, "packs", str(DEFAULT_PACKS))))
    vault = EvidenceVault(vault_root) if do_pack else None
    if do_pack:
        packs_root.mkdir(parents=True, exist_ok=True)

    print(f"Watching {folder} (Ctrl-C to stop)...", file=out)
    mode = "detect + analyze + pack" if do_pack else "detect + analyze"
    print(f"Poll every {args.interval:g}s — {mode}", file=out)
    if move_to is not None:
        print(f"Processed files will move to {move_to}", file=out)
    if do_pack:
        print(f"Evidence packs -> {packs_root}", file=out)
    out.flush()

    processed: set[Path] = set()
    pending_size: dict[Path, int] = {}
    total = scams = errors = 0
    iterations = 0
    # Size-stability settle is short even when --interval is long (e.g. hourly).
    settle = min(2.0, max(0.5, float(args.interval) if args.interval < 2 else 2.0))
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
                    pending_size[path] = size  # not yet stable; recheck after settle
                    _sleep(settle)
                    try:
                        size2 = path.stat().st_size
                    except OSError:
                        continue
                    if size2 != size:
                        pending_size[path] = size2
                        continue
                    size = size2
                try:
                    parsed = parse_eml_bytes(read_message_file(path))
                    total += 1
                    stamp = time.strftime("%H:%M:%S")
                    hit = _report(
                        parsed,
                        router=router,
                        escalate=args.escalate,
                        show_all=args.all,
                        out=out,
                        prefix=f"[{stamp}] {path.name}",
                    )
                    if hit:
                        scams += 1
                    if vault is not None:
                        pack = build_pack(
                            path,
                            vault=vault,
                            packs_root=packs_root,
                            enrich_provenance=True,
                        )
                        print(
                            f"    [pack] {pack.analysis.verdict} -> {pack.directory}",
                            file=out,
                        )
                except Exception as exc:
                    errors += 1
                    stamp = time.strftime("%H:%M:%S")
                    print(f"[{stamp}] {path.name}: skipped ({exc})", file=out)
                if move_to is not None:
                    try:
                        _move_processed(path, move_to)
                    except OSError as exc:
                        print(f"    move failed: {exc}", file=out)
                        processed.add(path)
                    else:
                        pending_size.pop(path, None)
                        # File left the inbox; no need to keep it in `processed`.
                        continue
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
    watch.add_argument(
        "--move-processed",
        nargs="?",
        const=str(DEFAULT_PROCESSED_FOLDER),
        default=None,
        metavar="DIR",
        help="after analysis, move the file out of the watch folder "
        f"(default DIR: {DEFAULT_PROCESSED_FOLDER})",
    )
    watch.add_argument(
        "--pack",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="after each stable drop: vault + FR/EN evidence pack (default: on)",
    )
    watch.add_argument(
        "--vault",
        default=str(DEFAULT_VAULT),
        help=f"evidence vault root when packing (default {DEFAULT_VAULT})",
    )
    watch.add_argument(
        "--packs",
        default=str(DEFAULT_PACKS),
        help=f"packs root when packing (default {DEFAULT_PACKS})",
    )
    watch.set_defaults(func=run_watch)


    pack = sub.add_parser(
        "pack",
        help="store .eml in the write-once vault and build a FR/EN complaint pack",
    )
    pack.add_argument(
        "--path",
        required=True,
        help="a .eml/.emlx file, or a folder of them (e.g. ~/ScamFighter/processed)",
    )
    pack.add_argument(
        "--vault",
        default=str(DEFAULT_VAULT),
        help=f"evidence vault root (default {DEFAULT_VAULT})",
    )
    pack.add_argument(
        "--packs",
        default=str(DEFAULT_PACKS),
        help=f"where to write complaint packs (default {DEFAULT_PACKS})",
    )
    pack.set_defaults(func=run_pack)
    return parser


def run_pack(args: argparse.Namespace, *, out: TextIO = sys.stdout) -> int:
    """Vault + bilingual complaint pack for one file or a folder of .eml/.emlx."""
    target = Path(os.path.expanduser(args.path))
    vault = EvidenceVault(Path(os.path.expanduser(args.vault)))
    packs_root = Path(os.path.expanduser(args.packs))
    packs_root.mkdir(parents=True, exist_ok=True)

    if target.is_file():
        paths = [target]
    elif target.is_dir():
        paths = sorted(
            {
                *target.glob("*.eml"),
                *target.glob("*.emlx"),
                *target.glob("**/*.eml"),
                *target.glob("**/*.emlx"),
            }
        )
        paths = [p for p in paths if p.is_file() and not p.is_symlink()]
    else:
        raise SystemExit(f"path not found: {target}")

    if not paths:
        print(f"No .eml/.emlx under {target}", file=out)
        return 1

    built = 0
    for path in paths:
        try:
            pack_obj = build_pack(path, vault=vault, packs_root=packs_root)
        except Exception as exc:
            print(f"[error] {path.name}: {exc}", file=out)
            continue
        built += 1
        print(
            f"[pack] {pack_obj.analysis.verdict} "
            f"sha256={pack_obj.sha256[:16]}… -> {pack_obj.directory}",
            file=out,
        )
        print(f"        FR: {pack_obj.directory / 'complaint_fr.md'}", file=out)
        print(f"        EN: {pack_obj.directory / 'complaint_en.md'}", file=out)
    print(f"\nBuilt {built} pack(s). Filing guide: docs/FILING.md", file=out)
    return 0 if built else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
