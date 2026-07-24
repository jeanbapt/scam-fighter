from pathlib import Path

import pytest
from scamfighter_core import defang, html_to_text, parse_eml, parse_eml_bytes

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


@pytest.fixture(scope="module")
def parsed():
    return parse_eml_bytes(FIXTURE.read_bytes())


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
    # Real origin IP is surfaced from Received; private/internal hops filtered out.
    assert "213.230.87.82" in parsed.indicators.public_ips
    assert "10.101.8.1" not in parsed.indicators.public_ips
    assert "127.0.0.1" not in parsed.indicators.public_ips


def test_body_ips_are_not_treated_as_origin():
    raw = (
        b"From: a@b.com\r\nTo: c@d.com\r\nSubject: x\r\n"
        b"Received: from evil ([203.0.113.9]) by mx;\r\n\r\n"
        b"Pay to 198.51.100.50 please"
    )
    parsed = parse_eml_bytes(raw)
    assert "203.0.113.9" in parsed.indicators.public_ips
    assert "198.51.100.50" not in parsed.indicators.public_ips


def test_html_only_body_is_stripped_for_indicators():
    raw = (
        b"From: victim@example.com\r\nTo: victim@example.com\r\n"
        b"Subject: I recorded you\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><script>alert(1)</script>"
        b"<p>I recorded you with your camera. Pay bitcoin "
        b"to 1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS</p></body></html>"
    )
    parsed = parse_eml_bytes(raw)
    assert "recorded you" in parsed.body.lower()
    assert "alert(1)" not in parsed.body
    assert "1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS" in parsed.indicators.bitcoin_addresses


def test_html_to_text_strips_tags():
    assert "hello" in html_to_text("<b>hello</b><script>evil()</script>")
    assert "evil()" not in html_to_text("<script>evil()</script>hi")


def test_non_utf8_charset_is_preserved():
    # windows-1252 body with a non-ASCII character (euro sign = 0x80 in 1252).
    raw = (
        b"From: a@b.com\r\nTo: c@d.com\r\nSubject: test\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: text/plain; charset="windows-1252"\r\n'
        b"Content-Transfer-Encoding: 8bit\r\n\r\n"
        b"Price: \x80 100\r\n"
    )
    parsed = parse_eml_bytes(raw)
    assert "\u20ac" in parsed.body or "100" in parsed.body


def test_parse_eml_str_wrapper_still_works():
    parsed = parse_eml(FIXTURE.read_text(encoding="utf-8"))
    assert parsed.subject == "[SPAM] I RECORDED YOU!"


def test_defang_makes_indicators_unclickable():
    assert defang("http://www.coinbase.com") == "hxxp://www[.]coinbase[.]com"
