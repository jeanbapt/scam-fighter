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
    assert a.is_scam is True
    assert a.confidence >= 0.8
    assert a.is_self_addressed is True
    assert a.auth_all_failing is True
    assert "1NBwsBzgJTX7KTAd8gZe53pLP73wtSEXDS" in a.bitcoin_addresses
    assert len(a.matched_phrases) >= 2
    assert "self_addressed" in a.irregularities


def test_analyze_benign_is_unknown():
    benign = parse_eml("From: a@b.com\nTo: c@d.com\nSubject: Lunch?\n\nWant lunch tomorrow?")
    a = analyze(benign)
    assert a.verdict == "unknown"
    assert a.is_sextortion is False
    assert a.is_scam is False
    assert a.irregularities == ()


def test_analyze_sofinco_style_brand_phishing_from_headers():
    # Passing auth must NOT clear brand phishing: display brand ≠ From domain.
    raw = (
        "Return-Path: <sofin-support@girlpowertalk.com>\r\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"
        "Received: from [105.74.2.100] by smtp-relay.gmail.com with ESMTPS;\r\n"
        "Message-ID: <6a.7b.SMTPIN_ADDED_MISSING@mx.google.com>\r\n"
        'From: "SOFINCO" <sofin-support@girlpowertalk.com>\r\n'
        "To: Recipients <sofin-support@girlpowertalk.com>\r\n"
        "Subject: Vous avez un nouveau message dans votre Espace Client.\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Me connecter\r\n"
        "--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        '<a href="https://trackingservice.monday.com/tracker/link?x=1">'
        "Me connecter</a>\r\n"
        "--b--\r\n"
    )
    a = analyze(parse_eml(raw))
    assert a.verdict == "phishing"
    assert a.is_phishing is True
    assert a.is_scam is True
    assert "display_name_domain_mismatch" in a.irregularities
    assert "self_addressed" in a.irregularities
    assert "cta_off_domain" in a.irregularities
    assert "synthetic_or_infra_message_id" in a.irregularities
    assert "auth_pass_does_not_validate_display_brand" in a.irregularities
    # Untrusted From: disambiguation must not clear the brand path.
    assert a.disambiguation == ()


def test_analyze_matching_display_brand_is_not_phishing():
    raw = (
        "From: GitHub <noreply@github.com>\r\n"
        "To: user@example.com\r\n"
        "Subject: [repo] Your dependency update\r\n"
        "Message-ID: <abc@github.com>\r\n\r\n"
        "A pull request was opened.\r\n"
    )
    a = analyze(parse_eml(raw))
    assert a.verdict == "unknown"
    assert "display_name_domain_mismatch" not in a.irregularities


def test_github_notification_fp_is_disambiguated():
    # Real FP: person/Dependabot display on notifications@github.com + CDN links.
    raw = (
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\r\n"
        "Message-ID: <tim@github.com>\r\n"
        "From: Dependabot <notifications@github.com>\r\n"
        "To: scam-fighter@noreply.github.com\r\n"
        "Subject: Re: [jeanbapt/scam-fighter] chore(deps): Bump actions\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        '<a href="https://github.com/jeanbapt/scam-fighter/pull/9">PR</a> '
        '<img src="https://avatars.githubusercontent.com/in/29110"/> '
        '<a href="https://docs.github.com/en/code-security">docs</a>\r\n'
    )
    a = analyze(parse_eml(raw))
    assert "display_name_domain_mismatch" in a.irregularities
    assert "cta_off_domain" in a.irregularities
    assert "trusted_from_domain_auth_pass" in a.disambiguation
    assert "person_display_on_trusted_notifier" in a.disambiguation
    assert "cta_same_org_family" in a.disambiguation
    assert a.verdict == "unknown"
    assert a.is_scam is False


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
