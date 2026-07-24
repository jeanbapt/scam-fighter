"""DNS blocklist lookups (Spamhaus ZEN, Barracuda) — query-only, no probing.

Uses DNS A lookups against public DNSBL zones. Suitable for low-volume
non-commercial use; commercial/high-volume operators should use licensed feeds.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Any

# Spamhaus ZEN return codes (A record last octet) — public docs.
_SPAMHAUS_CODES: dict[str, str] = {
    "2": "SBL (Spamhaus Block List)",
    "3": "SBL CSS",
    "4": "XBL (CBL)",
    "9": "SBL DROP/EDROP",
    "10": "PBL (ISP Policy Block List)",
    "11": "PBL (ISP Policy Block List)",
}


@dataclass(frozen=True)
class DnsblHit:
    zone: str
    return_ip: str
    meaning: str = ""


@dataclass(frozen=True)
class DnsblResult:
    ip: str
    listed: bool
    hits: tuple[DnsblHit, ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "listed": self.listed,
            "hits": [asdict(h) for h in self.hits],
            "error": self.error,
        }


def _reverse_ipv4(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        raise ValueError("only IPv4 DNSBL queries are supported")
    return ".".join(reversed(str(addr).split(".")))


def _lookup_a(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({str(x[4][0]) for x in infos})


def query_spamhaus_zen(ip: str) -> DnsblResult:
    """Query ``zen.spamhaus.org`` for *ip* (IPv4)."""
    try:
        rev = _reverse_ipv4(ip)
    except ValueError as exc:
        return DnsblResult(ip=ip, listed=False, error=str(exc))
    name = f"{rev}.zen.spamhaus.org"
    try:
        answers = _lookup_a(name)
    except OSError as exc:
        return DnsblResult(ip=ip, listed=False, error=str(exc))
    hits: list[DnsblHit] = []
    for ans in answers:
        last = ans.rsplit(".", 1)[-1]
        hits.append(
            DnsblHit(
                zone="zen.spamhaus.org",
                return_ip=ans,
                meaning=_SPAMHAUS_CODES.get(last, f"return code {last}"),
            )
        )
    return DnsblResult(ip=ip, listed=bool(hits), hits=tuple(hits))


def query_barracuda(ip: str) -> DnsblResult:
    """Query Barracuda Reputation Block List (``b.barracudacentral.org``)."""
    try:
        rev = _reverse_ipv4(ip)
    except ValueError as exc:
        return DnsblResult(ip=ip, listed=False, error=str(exc))
    name = f"{rev}.b.barracudacentral.org"
    try:
        answers = _lookup_a(name)
    except OSError as exc:
        return DnsblResult(ip=ip, listed=False, error=str(exc))
    hits = tuple(
        DnsblHit(zone="b.barracudacentral.org", return_ip=a, meaning="listed") for a in answers
    )
    return DnsblResult(ip=ip, listed=bool(hits), hits=hits)


def enrich_dnsbl(ip: str) -> dict[str, Any]:
    """Combined Spamhaus ZEN + Barracuda result for MCP / packs."""
    zen = query_spamhaus_zen(ip)
    bbl = query_barracuda(ip)
    return {
        "ip": ip,
        "spamhaus_zen": zen.to_dict(),
        "barracuda": bbl.to_dict(),
        "any_listed": zen.listed or bbl.listed,
    }
