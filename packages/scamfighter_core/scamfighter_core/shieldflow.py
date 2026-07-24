"""LiquidAI ShieldFlow integration (local egress proxy).

ShieldFlow installs as a **local MITM proxy** (not an in-process library). It
listens on a loopback port, installs a CA bundle, and tokenizes PII in outbound
LLM API traffic (reversible-by-default) before it leaves the device, per its
synced policy. Protection is therefore enforced on the wire: any HTTP client that
routes through the proxy and trusts the CA bundle is covered.

Integration model here:

* :func:`load_config` — discover the proxy URL + CA bundle from the environment or
  ``~/.shieldflow/proxy_env.sh``.
* :func:`is_active` — health-check the proxy (fresh heartbeat + reachable port).
* :func:`httpx_transport` / :func:`requests_transport` — kwargs to make a cloud
  LLM client route through ShieldFlow.
* :class:`ShieldFlowGuard` — an :class:`~scamfighter_core.egress_guard.EgressGuard`
  that confirms protection is live (marking semantic coverage) or **fails closed**.
  It does not redact in-process; the proxy tokenizes in transit.

No secrets are read or stored by this module (only the proxy URL and CA path).
"""

from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from scamfighter_core.egress_guard import GuardVerdict

DEFAULT_HOME = Path.home() / ".shieldflow"
_ENV_EXPORT_RE = re.compile(r'^\s*export\s+(\w+)="?([^"\n]*)"?\s*$', re.MULTILINE)
_HOST_PORT_RE = re.compile(r"https?://([^:/\s]+):(\d+)")
# If a heartbeat file exists it must be newer than this to trust the proxy.
_HEARTBEAT_MAX_AGE_SEC = 90.0


@dataclass(frozen=True)
class ShieldFlowConfig:
    """Where the ShieldFlow proxy lives and how to trust it."""

    proxy_url: str
    ca_bundle: str | None
    home: Path = DEFAULT_HOME

    @property
    def host_port(self) -> tuple[str, int] | None:
        m = _HOST_PORT_RE.search(self.proxy_url)
        return (m.group(1), int(m.group(2))) if m else None


def _parse_env_file(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return {m.group(1): m.group(2) for m in _ENV_EXPORT_RE.finditer(text)}


def load_config(home: Path = DEFAULT_HOME) -> ShieldFlowConfig | None:
    """Discover ShieldFlow config from the environment, then ``proxy_env.sh``.

    Returns ``None`` if no proxy URL can be found (ShieldFlow not installed here).
    """
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    ca = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")

    if not proxy:
        env = _parse_env_file(home / "proxy_env.sh")
        proxy = env.get("HTTPS_PROXY") or env.get("HTTP_PROXY")
        ca = ca or env.get("REQUESTS_CA_BUNDLE") or env.get("SSL_CERT_FILE")

    if not proxy:
        return None
    return ShieldFlowConfig(proxy_url=proxy, ca_bundle=ca, home=home)


def is_active(config: ShieldFlowConfig, *, timeout: float = 2.0) -> bool:
    """True when the proxy port is reachable and (if present) the heartbeat is fresh."""
    hp = config.host_port
    if hp is None:
        return False

    heartbeat = config.home / "proxy.heartbeat"
    if heartbeat.exists():
        try:
            if time.time() - heartbeat.stat().st_mtime > _HEARTBEAT_MAX_AGE_SEC:
                return False
        except OSError:
            return False

    host, port = hp
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def httpx_transport(config: ShieldFlowConfig) -> dict[str, object]:
    """Kwargs for an ``httpx.Client`` so cloud calls route through ShieldFlow."""
    return {"proxy": config.proxy_url, "verify": config.ca_bundle or True}


def requests_transport(config: ShieldFlowConfig) -> dict[str, object]:
    """Kwargs for a ``requests`` call so cloud calls route through ShieldFlow."""
    return {
        "proxies": {"http": config.proxy_url, "https": config.proxy_url},
        "verify": config.ca_bundle or True,
    }


class ShieldFlowGuard:
    """EgressGuard that gates cloud egress on ShieldFlow proxy health.

    Because ShieldFlow tokenizes PII in transit, this guard does not alter the
    text; it certifies that protection is live (``semantic_pii_checked=True``) or
    **fails closed** if the proxy is missing/unhealthy. Callers MUST route the
    actual cloud request through :func:`httpx_transport` / :func:`requests_transport`.
    """

    def __init__(
        self,
        config: ShieldFlowConfig | None,
        *,
        active_check: object = None,
    ) -> None:
        # An explicit ``None`` means "unconfigured" and fails closed; use
        # :meth:`discover` to auto-detect this machine's ShieldFlow install.
        self._config = config
        # ``active_check`` lets tests inject health without a live proxy.
        self._active_check = active_check if callable(active_check) else is_active

    @classmethod
    def discover(cls, *, active_check: object = None) -> ShieldFlowGuard:
        """Build a guard from this machine's ShieldFlow install (env / proxy_env.sh)."""
        return cls(load_config(), active_check=active_check)

    def inspect(self, text: str) -> GuardVerdict:
        if self._config is None:
            return GuardVerdict(
                allowed=False,
                text=text,
                reason="ShieldFlow not installed/discoverable (fail closed)",
            )
        if not self._active_check(self._config):
            return GuardVerdict(
                allowed=False,
                text=text,
                reason="ShieldFlow proxy not active (fail closed)",
            )
        return GuardVerdict(
            allowed=True,
            text=text,
            findings=("SHIELDFLOW_PROXY",),
            semantic_pii_checked=True,
            reason="protected by ShieldFlow egress proxy (PII tokenized in transit)",
        )
