from pathlib import Path

from scamfighter_core import MacMailSource, MailSource, parse_emlx

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def _emlx_bytes(message: str) -> bytes:
    raw = message.encode("utf-8")
    plist = b'<?xml version="1.0"?><plist><dict></dict></plist>'
    return f"{len(raw)}\n".encode() + raw + plist


def test_parse_emlx_strips_framing():
    message = FIXTURE.read_text(encoding="utf-8")
    out = parse_emlx(_emlx_bytes(message))
    assert out.startswith("Return-Path:")
    assert "I RECORDED YOU" in out
    assert "<plist>" not in out


def test_parse_emlx_passthrough_when_not_framed():
    plain = b"From: a@b.com\r\n\r\nhello"
    assert "hello" in parse_emlx(plain)


def test_macmail_source_reads_emlx(tmp_path: Path):
    box = tmp_path / "Inbox.mbox" / "Data" / "Messages"
    box.mkdir(parents=True)
    (box / "1.emlx").write_bytes(_emlx_bytes(FIXTURE.read_text(encoding="utf-8")))

    source = MacMailSource(root=tmp_path)
    assert isinstance(source, MailSource)
    parsed = list(source.iter_parsed())
    assert len(parsed) == 1
    assert parsed[0].subject == "[SPAM] I RECORDED YOU!"
    assert parsed[0].is_self_addressed is True


def test_macmail_limit(tmp_path: Path):
    box = tmp_path / "Messages"
    box.mkdir(parents=True)
    for i in range(3):
        (box / f"{i}.emlx").write_bytes(_emlx_bytes(FIXTURE.read_text(encoding="utf-8")))
    assert len(list(MacMailSource(root=tmp_path).iter_parsed(limit=2))) == 2
