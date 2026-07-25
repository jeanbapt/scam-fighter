"""Public provenance enrichment (RDAP / DNS) — defensive, no probing.

Only queries public registries and DNS. Never connects to attacker IPs beyond
what RDAP/WHOIS/DNS require. Results are meant for complaint packs.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RdapEntity:
    handle: str
    roles: tuple[str, ...]
    emails: tuple[str, ...]
    name: str = ""


@dataclass(frozen=True)
class IpProvenance:
    ip: str
    network_name: str = ""
    country: str = ""
    start_address: str = ""
    end_address: str = ""
    abuse_emails: tuple[str, ...] = ()
    entities: tuple[RdapEntity, ...] = ()
    reverse_dns: tuple[str, ...] = ()
    rdap_source: str = ""
    error: str = ""


@dataclass(frozen=True)
class DomainProvenance:
    domain: str
    registrar: str = ""
    abuse_email: str = ""
    name_servers: tuple[str, ...] = ()
    a_records: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class BtcProvenance:
    address: str
    tx_count: int | None = None
    funded_sum_sats: int | None = None
    explorer: str = ""
    error: str = ""


@dataclass(frozen=True)
class ProvenanceReport:
    ips: tuple[IpProvenance, ...] = ()
    domains: tuple[DomainProvenance, ...] = ()
    bitcoin: tuple[BtcProvenance, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ips": [asdict(i) for i in self.ips],
            "domains": [asdict(d) for d in self.domains],
            "bitcoin": [asdict(b) for b in self.bitcoin],
            "notes": list(self.notes),
        }


def _http_json(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url!r}")
    req = urllib.request.Request(  # noqa: S310 — https-only, public registries
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "scamfighter-provenance/0.1 (defensive research)",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected
        data = json.loads(resp.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def _vcard_emails(entity: dict[str, Any]) -> tuple[str, ...]:
    emails: list[str] = []
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ()
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == "email":
            emails.append(str(item[-1]))
    return tuple(dict.fromkeys(emails))


def _vcard_fn(entity: dict[str, Any]) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == "fn":
            return str(item[-1])
    return ""


def reverse_dns(ip: str) -> tuple[str, ...]:
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return tuple(dict.fromkeys([name, *aliases]))
    except (socket.herror, socket.gaierror, OSError):
        return ()


def enrich_ip(ip: str) -> IpProvenance:
    """RDAP lookup via bootstrap (rdap.org) then common RIRs on failure."""
    urls = (
        f"https://rdap.org/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
        f"https://rdap.arin.net/registry/ip/{ip}",
    )
    last_err = ""
    for url in urls:
        try:
            data = _http_json(url)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
            last_err = str(exc)
            continue
        entities: list[RdapEntity] = []
        abuse: list[str] = []
        for ent in data.get("entities") or []:
            if not isinstance(ent, dict):
                continue
            roles = tuple(str(r) for r in (ent.get("roles") or []))
            emails = _vcard_emails(ent)
            entities.append(
                RdapEntity(
                    handle=str(ent.get("handle") or ""),
                    roles=roles,
                    emails=emails,
                    name=_vcard_fn(ent),
                )
            )
            if "abuse" in roles:
                abuse.extend(emails)
        return IpProvenance(
            ip=ip,
            network_name=str(data.get("name") or ""),
            country=str(data.get("country") or ""),
            start_address=str(data.get("startAddress") or ""),
            end_address=str(data.get("endAddress") or ""),
            abuse_emails=tuple(dict.fromkeys(abuse)),
            entities=tuple(entities),
            reverse_dns=reverse_dns(ip),
            rdap_source=url,
        )
    return IpProvenance(ip=ip, reverse_dns=reverse_dns(ip), error=last_err or "rdap failed")


_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


def enrich_domain(domain: str) -> DomainProvenance:
    domain = domain.strip(".").lower()
    if not _DOMAIN_RE.match(domain):
        return DomainProvenance(domain=domain, error="invalid domain")
    a_recs: list[str] = []
    mx_recs: list[str] = []
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        a_recs = sorted({str(x[4][0]) for x in infos})
    except OSError as exc:
        return DomainProvenance(domain=domain, error=f"dns A: {exc}")
    # MX via dnspython is nicer; stick to dig-less stdlib: no MX in socket — leave empty
    # unless we shell out. Prefer empty over adding a dependency.
    return DomainProvenance(
        domain=domain,
        a_records=tuple(a_recs),
        mx_records=tuple(mx_recs),
    )


def enrich_btc(address: str) -> BtcProvenance:
    url = f"https://blockstream.info/api/address/{address}"
    try:
        data = _http_json(url)
        chain_stats = data.get("chain_stats")
        stats: dict[str, Any] = chain_stats if isinstance(chain_stats, dict) else {}
        return BtcProvenance(
            address=address,
            tx_count=int(stats.get("tx_count") or 0),
            funded_sum_sats=int(stats.get("funded_txo_sum") or 0),
            explorer="https://blockstream.info/address/" + address,
        )
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        TimeoutError,
        ValueError,
        TypeError,
    ) as exc:
        return BtcProvenance(address=address, error=str(exc))


def enrich(
    *,
    ips: list[str] | tuple[str, ...] = (),
    domains: list[str] | tuple[str, ...] = (),
    bitcoin: list[str] | tuple[str, ...] = (),
    connecting_ip: str | None = None,
) -> ProvenanceReport:
    """Enrich IOCs. ``connecting_ip`` is the SMTP client OVH actually accepted (highest weight)."""
    notes: list[str] = []
    if connecting_ip:
        notes.append(
            f"Highest-weight origin: SMTP client-ip accepted by the mailbox MX = {connecting_ip} "
            "(from Authentication-Results / Received-SPF). Earlier Received hops may be forged."
        )
    ordered_ips = [*([connecting_ip] if connecting_ip else []), *ips]
    ip_rows = tuple(enrich_ip(ip) for ip in dict.fromkeys(ordered_ips))
    dom_rows = tuple(enrich_domain(d) for d in dict.fromkeys(domains))
    btc_rows = tuple(enrich_btc(a) for a in dict.fromkeys(bitcoin))
    for b in btc_rows:
        if b.tx_count == 0:
            notes.append(
                f"BTC {b.address} has 0 on-chain transactions "
                "(unused ransom address — common in mass campaigns)."
            )
    return ProvenanceReport(ips=ip_rows, domains=dom_rows, bitcoin=btc_rows, notes=tuple(notes))


def format_provenance_markdown(report: ProvenanceReport, *, lang: str = "en") -> str:
    """Human-readable provenance section for complaint packs."""
    lines: list[str] = []
    if lang == "fr":
        lines.append("# Enrichissement de provenance (sources publiques)")
        lines.append("")
        lines.append(
            "> Requetes RDAP/DNS/explorateur BTC uniquement. Aucun scan ni connexion "
            "vers l'infrastructure suspecte au-dela des annuaires publics."
        )
    else:
        lines.append("# Provenance enrichment (public sources only)")
        lines.append("")
        lines.append(
            "> RDAP / DNS / BTC explorer lookups only. No port scans or connections to "
            "suspect hosts beyond public registries."
        )
    lines.append("")
    if report.notes:
        lines.append("## Notes")
        for n in report.notes:
            lines.append(f"- {n}")
        lines.append("")
    lines.append("## IP networks")
    for ip in report.ips:
        if ip.error and not ip.network_name:
            lines.append(f"- `{ip.ip}` — lookup failed: {ip.error}")
            continue
        abuse = ", ".join(ip.abuse_emails) or "(see RIR whois)"
        ptr = ", ".join(ip.reverse_dns) or "(none)"
        lines.append(
            f"- `{ip.ip}` — **{ip.network_name or '?'}** / {ip.country or '?'} "
            f"({ip.start_address}-{ip.end_address}); PTR={ptr}; abuse={abuse}"
        )
    lines.append("")
    lines.append("## Domains")
    for d in report.domains:
        if d.error and not d.a_records:
            lines.append(f"- `{d.domain}` — {d.error}")
            continue
        lines.append(
            f"- `{d.domain}` A={', '.join(d.a_records) or '(none)'}; "
            f"registrar={d.registrar or '(see whois)'}; abuse={d.abuse_email or '(see whois)'}"
        )
    lines.append("")
    lines.append("## Bitcoin")
    for b in report.bitcoin:
        if b.error:
            lines.append(f"- `{b.address}` — {b.error}")
        else:
            lines.append(
                f"- `{b.address}` — tx_count={b.tx_count}, funded_sats={b.funded_sum_sats}; "
                f"{b.explorer}"
            )
    lines.append("")
    return "\n".join(lines)
