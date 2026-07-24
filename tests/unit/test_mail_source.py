from pathlib import Path

import pytest
from scamfighter_core import (
    MAX_MESSAGE_BYTES,
    FolderSource,
    MacMailSource,
    MailSource,
    MessageTooLarge,
    parse_emlx,
    read_message_file,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def _emlx_bytes(message: str | bytes) -> bytes:
    raw = message.encode("utf-8") if isinstance(message, str) else message
    plist = b'<?xml version="1.0"?><plist><dict></dict></plist>'
    return f"{len(raw)}\n".encode() + raw + plist


def test_parse_emlx_strips_framing():
    message = FIXTURE.read_bytes()
    out = parse_emlx(_emlx_bytes(message))
    assert out.startswith(b"Return-Path:")
    assert b"I RECORDED YOU" in out
    assert b"<plist>" not in out


def test_parse_emlx_passthrough_when_not_framed():
    plain = b"From: a@b.com\r\n\r\nhello"
    assert b"hello" in parse_emlx(plain)


def test_macmail_source_reads_emlx(tmp_path: Path):
    box = tmp_path / "Inbox.mbox" / "Data" / "Messages"
    box.mkdir(parents=True)
    (box / "1.emlx").write_bytes(_emlx_bytes(FIXTURE.read_bytes()))

    source = MacMailSource(root=tmp_path)
    assert isinstance(source, MailSource)
    parsed = list(source.iter_parsed())
    assert len(parsed) == 1
    assert parsed[0].subject == "[SPAM] I RECORDED YOU!"
    assert parsed[0].is_self_addressed is True


def test_folder_source_reads_eml_and_emlx(tmp_path: Path):
    message = FIXTURE.read_text(encoding="utf-8")
    (tmp_path / "a.eml").write_text(message, encoding="utf-8")
    (tmp_path / "b.emlx").write_bytes(_emlx_bytes(message))

    source = FolderSource(tmp_path)
    assert isinstance(source, MailSource)
    parsed = list(source.iter_parsed())
    assert len(parsed) == 2
    assert all(p.subject == "[SPAM] I RECORDED YOU!" for p in parsed)


def test_folder_source_missing_dir_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        FolderSource(tmp_path / "nope")


def test_folder_source_skips_symlinks(tmp_path: Path):
    secret = tmp_path / "outside"
    secret.mkdir()
    target = secret / "secret.eml"
    target.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "link.eml").symlink_to(target)
    (inbox / "real.eml").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    paths = list(FolderSource(inbox).iter_message_paths())
    assert len(paths) == 1
    assert paths[0].name == "real.eml"
    assert len(list(FolderSource(inbox).iter_parsed())) == 1


def test_oversized_message_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("scamfighter_core.mail_source.MAX_MESSAGE_BYTES", 64)
    path = tmp_path / "big.eml"
    path.write_bytes(b"From: a@b.com\r\n\r\n" + b"x" * 200)
    with pytest.raises(MessageTooLarge):
        read_message_file(path)
    # FolderSource skips oversized files rather than crashing.
    assert list(FolderSource(tmp_path).iter_parsed()) == []
    assert MAX_MESSAGE_BYTES > 0  # constant still exported


def test_macmail_limit(tmp_path: Path):
    box = tmp_path / "Messages"
    box.mkdir(parents=True)
    for i in range(3):
        (box / f"{i}.emlx").write_bytes(_emlx_bytes(FIXTURE.read_bytes()))
    assert len(list(MacMailSource(root=tmp_path).iter_parsed(limit=2))) == 2
