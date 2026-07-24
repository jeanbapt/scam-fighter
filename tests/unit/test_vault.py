from pathlib import Path

import pytest
from scamfighter_core import EvidenceVault, VaultConflict, VaultError


def test_put_eml_is_content_addressed(tmp_path: Path):
    vault = EvidenceVault(tmp_path / "evidence")
    data = b"From: a@b.com\r\n\r\nhello"
    obj = vault.put_eml(data, source_name="x.eml")
    assert obj.sha256 == EvidenceVault.hash_bytes(data)
    assert obj.path.exists()
    assert obj.path.read_bytes() == data
    assert obj.already_present is False

    again = vault.put_eml(data, source_name="y.eml")
    assert again.sha256 == obj.sha256
    assert again.already_present is True


def test_conflict_on_different_bytes_same_path_impossible(tmp_path: Path):
    # Different content -> different hash dirs; conflict only if file mutated.
    vault = EvidenceVault(tmp_path / "evidence")
    data = b"From: a@b.com\r\n\r\none"
    obj = vault.put_eml(data)
    # Tamper the stored file while keeping the path/hash name.
    obj.path.write_bytes(b"From: a@b.com\r\n\r\nTAMPERED")
    with pytest.raises(VaultConflict):
        vault.put_eml(data)


def test_empty_rejected(tmp_path: Path):
    vault = EvidenceVault(tmp_path / "evidence")
    with pytest.raises(VaultError):
        vault.put_eml(b"")


def test_get_rejects_non_hex_sha(tmp_path: Path):
    vault = EvidenceVault(tmp_path / "evidence")
    with pytest.raises(VaultError):
        vault.get("../../etc/passwd")
    with pytest.raises(VaultError):
        vault.object_dir("not-a-digest")
