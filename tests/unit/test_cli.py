import io
from pathlib import Path

from scamfighter_app import main
from scamfighter_app.cli import _build_parser, run_ingest, run_watch

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def _emlx_bytes(message: str) -> bytes:
    raw = message.encode("utf-8")
    return f"{len(raw)}\n".encode() + raw + b"<?xml?><plist></plist>"


def test_ingest_macmail_reports_scam(tmp_path: Path):
    box = tmp_path / "Messages"
    box.mkdir(parents=True)
    (box / "1.emlx").write_bytes(_emlx_bytes(FIXTURE.read_text(encoding="utf-8")))

    args = _build_parser().parse_args(["ingest", "--source", "macmail", "--path", str(tmp_path)])
    out = io.StringIO()
    rc = run_ingest(args, out=out)
    text = out.getvalue()
    assert rc == 0
    assert "[SCAM] sextortion" in text
    assert "1 sextortion hit" in text


def test_watch_processes_existing_drop(tmp_path: Path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "mail-1.eml").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    args = _build_parser().parse_args(
        ["watch", "--path", str(inbox), "--interval", "0", "--no-pack"]
    )
    out = io.StringIO()
    # A file needs one tick to be seen and one to be confirmed stable, so run a
    # few iterations with a no-op sleep.
    rc = run_watch(args, out=out, _sleep=lambda _s: None, _max_iterations=3)
    text = out.getvalue()
    assert rc == 0
    assert "mail-1.eml" in text
    assert "[SCAM] sextortion" in text
    assert "1 sextortion hit" in text


def test_watch_survives_poison_message(tmp_path: Path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "poison.eml").write_bytes(b"\xff\xfe\x00not-a-valid-message")
    (inbox / "good.eml").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    args = _build_parser().parse_args(
        ["watch", "--path", str(inbox), "--interval", "0", "--no-pack"]
    )
    out = io.StringIO()
    rc = run_watch(args, out=out, _sleep=lambda _s: None, _max_iterations=4)
    text = out.getvalue()
    assert rc == 0
    # Watcher keeps running and still reports the good message.
    assert "[SCAM] sextortion" in text or "sextortion hit" in text


def test_watch_creates_missing_folder(tmp_path: Path):
    inbox = tmp_path / "does-not-exist-yet"
    args = _build_parser().parse_args(
        ["watch", "--path", str(inbox), "--interval", "0", "--no-pack"]
    )
    out = io.StringIO()
    rc = run_watch(args, out=out, _sleep=lambda _s: None, _max_iterations=1)
    assert rc == 0
    assert inbox.is_dir()


def test_watch_move_processed(tmp_path: Path):
    inbox = tmp_path / "inbox"
    processed = tmp_path / "processed"
    inbox.mkdir()
    src = inbox / "mail-1.eml"
    src.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    args = _build_parser().parse_args(
        [
            "watch",
            "--path",
            str(inbox),
            "--interval",
            "0",
            "--move-processed",
            str(processed),
            "--no-pack",
        ]
    )
    out = io.StringIO()
    rc = run_watch(args, out=out, _sleep=lambda _s: None, _max_iterations=3)
    assert rc == 0
    assert not src.exists()
    assert (processed / "mail-1.eml").exists()
    assert processed.is_dir()


def test_watch_packs_on_detect(tmp_path: Path):
    from unittest.mock import patch

    from scamfighter_core import build_pack as real_build_pack

    inbox = tmp_path / "inbox"
    vault_dir = tmp_path / "evidence"
    packs = tmp_path / "packs"
    inbox.mkdir()
    (inbox / "mail-1.eml").write_bytes(FIXTURE.read_bytes())

    args = _build_parser().parse_args(
        [
            "watch",
            "--path",
            str(inbox),
            "--interval",
            "0",
            "--pack",
            "--vault",
            str(vault_dir),
            "--packs",
            str(packs),
        ]
    )
    out = io.StringIO()

    def _pack(path, *, vault, packs_root, enrich_provenance=True):
        return real_build_pack(
            path, vault=vault, packs_root=packs_root, enrich_provenance=False
        )

    with patch("scamfighter_app.cli.build_pack", side_effect=_pack):
        rc = run_watch(args, out=out, _sleep=lambda _s: None, _max_iterations=3)
    assert rc == 0
    assert "[pack]" in out.getvalue()
    assert any(packs.iterdir())


def test_main_requires_command():
    try:
        main([])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit")
