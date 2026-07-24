"""LLM providers and routing (edge-first, guarded cloud escalation).

Routing policy:

* **Local by default** — :class:`OllamaLocalProvider` talks to a local Ollama; no
  egress guard needed because nothing leaves the device.
* **Cloud only as escalation** — :class:`OpenAICompatibleProvider` sends to an
  OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq, Mistral, ...). Every call
  first passes the fail-closed egress guard (in-process redaction + confirmation
  that ShieldFlow is live) and is routed through the ShieldFlow proxy so PII is
  tokenized in transit.

Note: ShieldFlow currently intercepts the providers in its policy (OpenAI,
Anthropic, Azure, Bedrock, Groq, Mistral, OpenRouter, Perplexity, DeepSeek, GitHub
Models, Cursor, ...). It does **not** list Ollama Cloud, so for guarded cloud
escalation use an OpenAI-compatible provider that ShieldFlow recognizes.

HTTP is done with the stdlib and an injectable sender so tests stay offline.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from scamfighter_core.egress_guard import EgressGuard, guard_cloud_egress
from scamfighter_core.shieldflow import ShieldFlowConfig

# (url, headers, body) -> response text
HttpSender = Callable[[str, dict[str, str], bytes], str]


def _post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    proxy: str | None = None,
    cafile: str | None = None,
    timeout: float = 60.0,
) -> str:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    if proxy:
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(
                context=ssl.create_default_context(cafile=cafile)
                if cafile
                else ssl.create_default_context()
            ),
        ]
        opener = urllib.request.build_opener(*handlers)
    else:
        opener = urllib.request.build_opener()
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _direct_sender() -> HttpSender:
    return lambda url, headers, body: _post(url, headers, body)


def _proxied_sender(config: ShieldFlowConfig) -> HttpSender:
    return lambda url, headers, body: _post(
        url, headers, body, proxy=config.proxy_url, cafile=config.ca_bundle
    )


@runtime_checkable
class LLMProvider(Protocol):
    """A text-completion provider."""

    is_local: bool

    def complete(self, prompt: str, *, system: str | None = None) -> str: ...


class OllamaLocalProvider:
    """Local Ollama (default). No content leaves the device."""

    is_local = True

    def __init__(
        self,
        model: str = "qwen2.5:3b",
        *,
        host: str = "http://127.0.0.1:11434",
        sender: HttpSender | None = None,
    ) -> None:
        self._model = model
        self._host = host.rstrip("/")
        self._send = sender or _direct_sender()

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        body = {
            "model": self._model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
        }
        raw = self._send(
            f"{self._host}/api/generate",
            {"Content-Type": "application/json"},
            json.dumps(body).encode("utf-8"),
        )
        return str(json.loads(raw).get("response", ""))


class OpenAICompatibleProvider:
    """Guarded cloud escalation via an OpenAI-compatible endpoint.

    Prompts pass the egress guard (fail-closed) and are sent through the ShieldFlow
    proxy so PII is tokenized in transit.
    """

    is_local = False

    def __init__(
        self,
        model: str,
        *,
        base_url: str,
        api_key: str,
        guard: EgressGuard,
        shieldflow: ShieldFlowConfig,
        sender: HttpSender | None = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._guard = guard
        self._send = sender or _proxied_sender(shieldflow)

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        # Fail-closed: redact in-process and confirm ShieldFlow is live before send.
        safe_prompt = guard_cloud_egress(prompt, self._guard)
        safe_system = guard_cloud_egress(system, self._guard) if system else None

        messages: list[dict[str, str]] = []
        if safe_system:
            messages.append({"role": "system", "content": safe_system})
        messages.append({"role": "user", "content": safe_prompt})

        body = {"model": self._model, "messages": messages}
        raw = self._send(
            f"{self._base_url}/chat/completions",
            {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            json.dumps(body).encode("utf-8"),
        )
        data = json.loads(raw)
        return str(data["choices"][0]["message"]["content"])


class ProviderRouter:
    """Route to local by default; escalate to guarded cloud only when asked."""

    def __init__(self, local: LLMProvider, cloud: LLMProvider | None = None) -> None:
        self._local = local
        self._cloud = cloud

    def complete(self, prompt: str, *, system: str | None = None, escalate: bool = False) -> str:
        if escalate:
            if self._cloud is None:
                raise RuntimeError("cloud escalation requested but no cloud provider configured")
            return self._cloud.complete(prompt, system=system)
        return self._local.complete(prompt, system=system)
