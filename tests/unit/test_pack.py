from pathlib import Path

from scamfighter_core import EvidenceVault, build_pack

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def test_build_pack_writes_fr_en_and_manifest(tmp_path: Path):
    vault = EvidenceVault(tmp_path / "evidence")
    packs = tmp_path / "packs"
    eml = tmp_path / "sample.eml"
    eml.write_bytes(FIXTURE.read_bytes())

    pack = build_pack(eml, vault=vault, packs_root=packs)
    assert pack.analysis.verdict == "sextortion"
    assert (pack.directory / "complaint_fr.md").exists()
    assert (pack.directory / "complaint_en.md").exists()
    assert (pack.directory / "message.eml").exists()
    assert (pack.directory / "iocs.txt").exists()
    assert (pack.directory / "MANIFEST.sha256").exists()
    assert (pack.directory / "meta.json").exists()

    fr = (pack.directory / "complaint_fr.md").read_text(encoding="utf-8")
    en = (pack.directory / "complaint_en.md").read_text(encoding="utf-8")
    assert "THESEE" in fr
    assert "ovhcloud.com" in fr.lower() or "OVH" in fr
    assert "SHA-256" in en
    assert pack.sha256 in fr
    assert "1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS" in (pack.directory / "iocs.txt").read_text(
        encoding="utf-8"
    )
