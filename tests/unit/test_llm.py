import json

import pytest
from scamfighter_core import (
    CompositeEgressGuard,
    DeterministicRedactor,
    EgressBlocked,
    LLMProvider,
    OllamaLocalProvider,
    OpenAICompatibleProvider,
    ProviderRouter,
    ShieldFlowConfig,
    ShieldFlowGuard,
)

CFG = ShieldFlowConfig(proxy_url="http://127.0.0.1:47821", ca_bundle=None)


def test_local_provider_conforms_and_completes():
    captured = {}

    def sender(url: str, headers: dict, body: bytes) -> str:
        captured["url"] = url
        captured["body"] = json.loads(body)
        return json.dumps({"response": "hello from local"})

    p = OllamaLocalProvider("qwen2.5:3b", sender=sender)
    assert isinstance(p, LLMProvider)
    assert p.is_local is True
    assert p.complete("hi") == "hello from local"
    assert captured["url"].endswith("/api/generate")


def test_cloud_provider_redacts_before_send_and_routes():
    captured = {}

    def sender(url: str, headers: dict, body: bytes) -> str:
        captured["url"] = url
        captured["auth"] = headers.get("Authorization")
        captured["body"] = json.loads(body)
        return json.dumps({"choices": [{"message": {"content": "ok"}}]})

    guard = CompositeEgressGuard(
        [DeterministicRedactor(), ShieldFlowGuard(CFG, active_check=lambda _c: True)],
        strict=True,
    )
    p = OpenAICompatibleProvider(
        "gpt-4o-mini",
        base_url="https://api.openai.com/v1",
        api_key="sk-test",
        guard=guard,
        shieldflow=CFG,
        sender=sender,
    )
    out = p.complete("email me at victim@example.com")
    assert out == "ok"
    # PII was redacted in-process before leaving.
    user_msg = captured["body"]["messages"][-1]["content"]
    assert "victim@example.com" not in user_msg
    assert "[REDACTED_EMAIL]" in user_msg
    assert captured["auth"] == "Bearer sk-test"
    assert captured["url"].endswith("/chat/completions")


def test_cloud_provider_fails_closed_when_shieldflow_down():
    guard = CompositeEgressGuard(
        [DeterministicRedactor(), ShieldFlowGuard(CFG, active_check=lambda _c: False)],
        strict=True,
    )
    p = OpenAICompatibleProvider(
        "gpt-4o-mini",
        base_url="https://api.openai.com/v1",
        api_key="sk-test",
        guard=guard,
        shieldflow=CFG,
        sender=lambda u, h, b: pytest.fail("must not send when guard blocks"),
    )
    with pytest.raises(EgressBlocked):
        p.complete("anything")


def test_router_defaults_local_and_escalates():
    local = OllamaLocalProvider(sender=lambda u, h, b: json.dumps({"response": "local"}))
    cloud_calls = {"n": 0}

    class FakeCloud:
        is_local = False

        def complete(self, prompt: str, *, system: str | None = None) -> str:
            cloud_calls["n"] += 1
            return "cloud"

    router = ProviderRouter(local, FakeCloud())
    assert router.complete("x") == "local"
    assert router.complete("x", escalate=True) == "cloud"
    assert cloud_calls["n"] == 1


def test_router_escalate_without_cloud_raises():
    local = OllamaLocalProvider(sender=lambda u, h, b: json.dumps({"response": "local"}))
    with pytest.raises(RuntimeError):
        ProviderRouter(local).complete("x", escalate=True)
