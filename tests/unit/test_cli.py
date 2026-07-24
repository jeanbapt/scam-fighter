import io
from pathlib import Path

from scamfighter_app import main
from scamfighter_app.cli import _build_parser, run_ingest

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


def test_main_requires_command():
    try:
        main([])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit")
