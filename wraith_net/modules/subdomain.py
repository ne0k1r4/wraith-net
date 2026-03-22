"""
wraith_net/modules/subdomain.py — Passive subdomain enumeration
Sources: crt.sh, HackerTarget, AlienVault OTX, ThreatCrowd, RapidDNS, BufferOver
"""

import re
from typing import Optional
from wraith_net.utils.helpers import http_get_json, http_get, normalize_domain, rate_limit
from wraith_net.core.config import OTX_API_KEY, HTTP_TIMEOUT


def _crtsh(domain: str) -> set[str]:
    """Certificate Transparency logs via crt.sh."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data:
        return set()
    subs = set()
    for entry in data:
        names = entry.get("name_value", "")
        for name in names.split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}") or name == domain:
                subs.add(name.lower())
    return subs


def _hackertarget(domain: str) -> set[str]:
    """HackerTarget free API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    raw = http_get(url, timeout=HTTP_TIMEOUT)
    if not raw:
        return set()
    subs = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        parts = line.split(",")
        if parts and parts[0].endswith(f".{domain}"):
            subs.add(parts[0].strip().lower())
    return subs


def _alienvault(domain: str) -> set[str]:
    """AlienVault OTX passive DNS."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    data = http_get_json(url, headers=headers, timeout=HTTP_TIMEOUT)
    if not data:
        return set()
    subs = set()
    for record in data.get("passive_dns", []):
        hostname = record.get("hostname", "").lower()
        if hostname.endswith(f".{domain}") or hostname == domain:
            subs.add(hostname)
    return subs


def _rapiddns(domain: str) -> set[str]:
    """RapidDNS subdomain search."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    raw = http_get(url, timeout=HTTP_TIMEOUT)
    if not raw:
        return set()
    text = raw.decode("utf-8", errors="replace")
    pattern = rf'([a-zA-Z0-9\-\.]+\.{re.escape(domain)})'
    return {m.lower() for m in re.findall(pattern, text)}


def _bufferover(domain: str) -> set[str]:
    """BufferOver.run DNS dataset."""
    url = f"https://tls.bufferover.run/dns?q=.{domain}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data:
        return set()
    subs = set()
    for record in data.get("Results", []):
        # format: "IP,subdomain.domain.com"
        parts = record.split(",")
        if len(parts) >= 2:
            host = parts[-1].strip().lower()
            if host.endswith(f".{domain}"):
                subs.add(host)
    return subs


def _threatcrowd(domain: str) -> set[str]:
    """ThreatCrowd domain report."""
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data or data.get("response_code") == "0":
        return set()
    subs = set()
    for sub in data.get("subdomains", []):
        sub = sub.strip().lower()
        if sub.endswith(f".{domain}") or sub == domain:
            subs.add(sub)
    return subs


def run(target: str, progress_cb=None) -> dict:
    """
    Run all passive subdomain enumeration sources.
    Returns: {
        "subdomains": sorted list of unique subdomains,
        "count": int,
        "sources": {source: count},
    }
    """
    domain = normalize_domain(target)

    sources = {
        "crt.sh":       _crtsh,
        "HackerTarget": _hackertarget,
        "AlienVault":   _alienvault,
        "RapidDNS":     _rapiddns,
        "BufferOver":   _bufferover,
        "ThreatCrowd":  _threatcrowd,
    }

    all_subs: set[str] = set()
    source_counts = {}

    for name, fn in sources.items():
        if progress_cb:
            progress_cb(f"subdomain [{name}]")
        try:
            result = fn(domain)
            source_counts[name] = len(result)
            all_subs |= result
        except Exception:
            source_counts[name] = 0
        rate_limit(0.4)

    return {
        "subdomains": sorted(all_subs),
        "count": len(all_subs),
        "sources": source_counts,
        "domain": domain,
    }
