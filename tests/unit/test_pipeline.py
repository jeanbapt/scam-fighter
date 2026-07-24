import json
from pathlib import Path

from scamfighter_core import (
    OllamaLocalProvider,
    ProviderRouter,
    analyze,
    parse_eml,
    summarize,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "i_recorded_you.eml"


def _parsed():
    return parse_eml(FIXTURE.read_text(encoding="utf-8"))


def test_analyze_flags_sextortion():
    a = analyze(_parsed())
    assert a.verdict == "sextortion"
    assert a.is_sextortion is True
    assert a.confidence >= 0.8
    assert a.is_self_addressed is True
    assert a.auth_all_failing is True
    assert "1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS" in a.bitcoin_addresses
    assert len(a.matched_phrases) >= 2


def test_analyze_benign_is_unknown():
    benign = parse_eml("From: a@b.com\nTo: c@d.com\nSubject: Lunch?\n\nWant lunch tomorrow?")
    a = analyze(benign)
    assert a.verdict == "unknown"
    assert a.is_sextortion is False


def test_summarize_uses_local_router_offline():
    seen = {}

    def sender(url: str, headers: dict, body: bytes) -> str:
        seen["body"] = json.loads(body)
        return json.dumps({"response": "This is a bluff. Do not pay. Report it."})

    router = ProviderRouter(OllamaLocalProvider(sender=sender))
    out = summarize(_parsed(), router)
    assert "Do not pay" in out
    # The prompt carried the subject to the (local) model.
    assert "RECORDED YOU" in seen["body"]["prompt"]
