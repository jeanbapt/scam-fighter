from pathlib import Path

import pytest
from scamfighter_core import defang, parse_eml

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


@pytest.fixture(scope="module")
def parsed():
    return parse_eml(FIXTURE.read_text(encoding="utf-8"))


def test_headers_are_parsed(parsed):
    assert parsed.subject == "[SPAM] I RECORDED YOU!"
    assert parsed.from_addr == "victim@example.com"
    assert parsed.to_addr == "victim@example.com"
    assert parsed.message_id == "<118849.118849@04538.com>"
    # The full Received chain is preserved for chain-of-custody / origin analysis.
    assert len(parsed.received_chain) >= 5


def test_self_addressed_spoof_is_detected(parsed):
    # The scam's whole "proof" is that From == To. We flag it explicitly.
    assert parsed.is_self_addressed is True


def test_authentication_debunks_the_sender(parsed):
    assert parsed.auth.spf == "softfail"
    assert parsed.auth.dkim == "none"
    assert parsed.auth.dmarc == "fail"
    assert parsed.auth.all_failing is True


def test_indicators_are_extracted(parsed):
    assert "1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS" in parsed.indicators.bitcoin_addresses
    assert "http://www.coinbase.com" in parsed.indicators.urls
    # Real origin IP is surfaced; private/internal hops are filtered out.
    assert "213.230.87.82" in parsed.indicators.public_ips
    assert "10.101.8.1" not in parsed.indicators.public_ips
    assert "127.0.0.1" not in parsed.indicators.public_ips


def test_defang_makes_indicators_unclickable():
    assert defang("http://www.coinbase.com") == "hxxp://www[.]coinbase[.]com"
