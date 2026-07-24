from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from scamfighter_core.dnsbl import DnsblHit, DnsblResult, enrich_dnsbl, query_spamhaus_zen
from scamfighter_core.filing import (
    ApprovalGate,
    confirm_action,
    draft_abuse_mailto,
    form_fill_plan,
    load_pack,
    request_spamhaus_submit,
    submit_spamhaus_email,
)
from scamfighter_core.pack import build_pack
from scamfighter_core.vault import EvidenceVault

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def _make_pack(tmp_path: Path):
    vault = EvidenceVault(tmp_path / "evidence")
    packs = tmp_path / "packs"
    eml = tmp_path / "sample.eml"
    eml.write_bytes(FIXTURE.read_bytes())
    return build_pack(eml, vault=vault, packs_root=packs, enrich_provenance=False)


def test_load_pack_and_mailto_draft(tmp_path: Path):
    pack = _make_pack(tmp_path)
    snap = load_pack(pack.directory)
    assert snap.sha256 == pack.sha256
    assert snap.has_message_eml
    draft = draft_abuse_mailto(snap, to="fraude@ovh.com", lang="fr")
    path = Path(draft["draft_path"])
    assert path.is_file()
    raw = path.read_bytes()
    assert b"fraude@ovh.com" in raw
    assert b"Content-Disposition: attachment" in raw or b'filename="message.eml"' in raw


def test_form_fill_plans(tmp_path: Path):
    pack = _make_pack(tmp_path)
    snap = load_pack(pack.directory)
    ovh = form_fill_plan("ovh_abuse", snap)
    assert ovh["auto_submit"] is False
    assert "ovhcloud.com" in ovh["urls"]["fr"]
    thesee = form_fill_plan("thesee", snap)
    assert thesee["human_required"] is True
    with pytest.raises(ValueError):
        form_fill_plan("nope", snap)


def test_spamhaus_confirm_gate_dry_run(tmp_path: Path):
    pack = _make_pack(tmp_path)
    snap = load_pack(pack.directory)
    req = request_spamhaus_submit(snap, reason="sextortion spam sample")
    token = req["approval_token"]
    with pytest.raises(PermissionError):
        submit_spamhaus_email(token, dry_run=True)
    confirm_action(token)
    result = submit_spamhaus_email(token, dry_run=True)
    assert result["status"] == "dry_run"
    with pytest.raises(KeyError):
        submit_spamhaus_email(token, dry_run=True)  # consumed


def test_approval_gate_ttl_and_mismatch():
    gate = ApprovalGate(ttl_seconds=60)
    token = gate.request("submit_spamhaus_email", {"x": 1})
    gate.confirm(token)
    with pytest.raises(PermissionError):
        gate.consume(token, expected_action="other")


def test_dnsbl_mock():
    fake = DnsblResult(
        ip="1.2.3.4",
        listed=True,
        hits=(DnsblHit(zone="zen.spamhaus.org", return_ip="127.0.0.4", meaning="XBL"),),
    )
    with (
        patch("scamfighter_core.dnsbl.query_spamhaus_zen", return_value=fake),
        patch(
            "scamfighter_core.dnsbl.query_barracuda",
            return_value=DnsblResult(ip="1.2.3.4", listed=False),
        ),
    ):
        out = enrich_dnsbl("1.2.3.4")
    assert out["any_listed"] is True
    assert out["spamhaus_zen"]["listed"] is True


def test_spamhaus_rejects_ipv6():
    r = query_spamhaus_zen("::1")
    assert r.listed is False
    assert r.error


def test_load_pack_rejects_path_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    packs = tmp_path / "packs"
    packs.mkdir()
    monkeypatch.setenv("SCAMFIGHTER_PACKS", str(packs))
    with pytest.raises(ValueError):
        load_pack("../etc")
    with pytest.raises(ValueError):
        load_pack("foo/../../bar")


def test_build_pack_rejects_oversized(tmp_path: Path):
    from scamfighter_core.mail_source import MAX_MESSAGE_BYTES, MessageTooLarge

    vault = EvidenceVault(tmp_path / "evidence")
    huge = tmp_path / "huge.eml"
    huge.write_bytes(b"x" * (MAX_MESSAGE_BYTES + 1))
    with pytest.raises(MessageTooLarge):
        build_pack(huge, vault=vault, packs_root=tmp_path / "packs", enrich_provenance=False)
