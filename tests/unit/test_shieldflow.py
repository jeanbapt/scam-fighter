from pathlib import Path

import pytest
from scamfighter_core import (
    CompositeEgressGuard,
    DeterministicRedactor,
    EgressBlocked,
    EgressGuard,
    ShieldFlowGuard,
    guard_cloud_egress,
    httpx_transport,
    load_config,
    requests_transport,
)

PROXY_ENV = """\
# ShieldFlow CLI proxy environment (managed automatically)
export HTTPS_PROXY="http://127.0.0.1:47821"
export HTTP_PROXY="http://127.0.0.1:47821"
export SSL_CERT_FILE="/tmp/sf/certs/sf-ca-bundle.pem"
export REQUESTS_CA_BUNDLE="/tmp/sf/certs/sf-ca-bundle.pem"
"""


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    # Isolate discovery from the real environment.
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    (tmp_path / "proxy_env.sh").write_text(PROXY_ENV, encoding="utf-8")
    return tmp_path


def test_load_config_parses_proxy_env(home: Path):
    cfg = load_config(home=home)
    assert cfg is not None
    assert cfg.proxy_url == "http://127.0.0.1:47821"
    assert cfg.host_port == ("127.0.0.1", 47821)
    assert cfg.ca_bundle == "/tmp/sf/certs/sf-ca-bundle.pem"


def test_load_config_returns_none_when_absent(tmp_path: Path, monkeypatch):
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    assert load_config(home=tmp_path) is None


def test_transport_helpers(home: Path):
    cfg = load_config(home=home)
    assert cfg is not None
    assert httpx_transport(cfg)["proxy"] == "http://127.0.0.1:47821"
    assert requests_transport(cfg)["proxies"]["https"] == "http://127.0.0.1:47821"


def test_guard_conforms_and_certifies_when_active(home: Path):
    cfg = load_config(home=home)
    guard = ShieldFlowGuard(cfg, active_check=lambda _c: True)
    assert isinstance(guard, EgressGuard)
    v = guard.inspect("secret stuff")
    assert v.allowed is True
    assert v.semantic_pii_checked is True
    assert "SHIELDFLOW_PROXY" in v.findings


def test_guard_fails_closed_when_inactive(home: Path):
    cfg = load_config(home=home)
    guard = ShieldFlowGuard(cfg, active_check=lambda _c: False)
    v = guard.inspect("secret stuff")
    assert v.allowed is False
    assert "not active" in v.reason


def test_guard_fails_closed_when_not_installed(tmp_path: Path, monkeypatch):
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    guard = ShieldFlowGuard(load_config(home=tmp_path))
    assert guard.inspect("x").allowed is False


def test_composite_with_shieldflow_active(home: Path):
    cfg = load_config(home=home)
    guard = CompositeEgressGuard(
        [DeterministicRedactor(), ShieldFlowGuard(cfg, active_check=lambda _c: True)],
        strict=True,
    )
    # Structured PII is masked in-process; ShieldFlow certifies transit protection.
    out = guard_cloud_egress("mail a@b.com to 1.2.3.4", guard)
    assert "a@b.com" not in out


def test_composite_blocks_when_shieldflow_down(home: Path):
    cfg = load_config(home=home)
    guard = CompositeEgressGuard(
        [DeterministicRedactor(), ShieldFlowGuard(cfg, active_check=lambda _c: False)],
        strict=True,
    )
    with pytest.raises(EgressBlocked):
        guard_cloud_egress("mail a@b.com", guard)
