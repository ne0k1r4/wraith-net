"""
wraith_net/modules/shodan_feed.py — Shodan & Censys threat intelligence
Falls back gracefully if API keys are absent.
"""

import json
from wraith_net.utils.helpers import http_get_json, http_get, resolve_domain, rate_limit
from wraith_net.core.config import (
    SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SEC, HTTP_TIMEOUT
)
import base64


# ── Shodan ────────────────────────────────────────────────────────────────────

def _shodan_host(ip: str) -> dict:
    if not SHODAN_API_KEY:
        return {"error": "No SHODAN_API_KEY set"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data:
        return {"error": "No response"}
    if "error" in data:
        return {"error": data["error"]}
    return {
        "ip": data.get("ip_str", ip),
        "org": data.get("org", ""),
        "isp": data.get("isp", ""),
        "asn": data.get("asn", ""),
        "country": data.get("country_name", ""),
        "city": data.get("city", ""),
        "os": data.get("os", ""),
        "ports": data.get("ports", []),
        "vulns": list(data.get("vulns", {}).keys()),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "last_update": data.get("last_update", ""),
        "services": [
            {
                "port": svc.get("port"),
                "transport": svc.get("transport", "tcp"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "cpe": svc.get("cpe", []),
                "banner": (svc.get("data", "")[:200] if svc.get("data") else ""),
            }
            for svc in data.get("data", [])
        ],
    }


def _shodan_dns(domain: str) -> dict:
    if not SHODAN_API_KEY:
        return {}
    url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data or "error" in data:
        return {}
    return {
        "subdomains": data.get("subdomains", []),
        "tags": data.get("tags", []),
        "more": data.get("more", False),
    }


# ── Censys ────────────────────────────────────────────────────────────────────

def _censys_ip(ip: str) -> dict:
    if not (CENSYS_API_ID and CENSYS_API_SEC):
        return {"error": "No CENSYS_API_ID / CENSYS_API_SECRET set"}
    creds = base64.b64encode(f"{CENSYS_API_ID}:{CENSYS_API_SEC}".encode()).decode()
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    import urllib.request
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {creds}",
            "User-Agent": "WRAITH-NET/1.0",
        }
    )
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return {}
    result = data.get("result", {})
    return {
        "ip": result.get("ip", ip),
        "asn": result.get("autonomous_system", {}).get("asn"),
        "org": result.get("autonomous_system", {}).get("name"),
        "country": result.get("location", {}).get("country"),
        "services": [
            {
                "port": svc.get("port"),
                "protocol": svc.get("transport_protocol"),
                "service_name": svc.get("service_name"),
                "product": svc.get("extended_service_name"),
                "cert": svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("subject_dn", ""),
            }
            for svc in result.get("services", [])
        ],
        "labels": result.get("labels", []),
    }


# ── Shodan InternetDB (no key needed) ─────────────────────────────────────────

def _internetdb(ip: str) -> dict:
    """Shodan InternetDB — free, no API key required."""
    url = f"https://internetdb.shodan.io/{ip}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data or "detail" in data:
        return {}
    return {
        "ip": ip,
        "ports": data.get("ports", []),
        "vulns": data.get("vulns", []),
        "cpes": data.get("cpes", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "source": "Shodan InternetDB (no-key)",
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, progress_cb=None) -> dict:
    """
    Fetch Shodan + Censys intelligence for target domain/IP.
    Returns comprehensive threat intel dict.
    """
    from wraith_net.utils.helpers import normalize_domain
    domain = normalize_domain(target)
    ips = resolve_domain(domain)
    ip = ips[0] if ips else domain

    results = {
        "domain": domain,
        "ip": ip,
        "all_ips": ips,
        "shodan": {},
        "shodan_dns": {},
        "shodan_free": {},
        "censys": {},
    }

    # Always try free InternetDB first
    if progress_cb:
        progress_cb("shodan [InternetDB]")
    results["shodan_free"] = _internetdb(ip)
    rate_limit(0.5)

    if SHODAN_API_KEY:
        if progress_cb:
            progress_cb("shodan [host lookup]")
        results["shodan"] = _shodan_host(ip)
        rate_limit(0.5)

        if progress_cb:
            progress_cb("shodan [DNS]")
        results["shodan_dns"] = _shodan_dns(domain)
        rate_limit(0.5)

    if CENSYS_API_ID and CENSYS_API_SEC:
        if progress_cb:
            progress_cb("censys [host lookup]")
        results["censys"] = _censys_ip(ip)

    # Aggregate vuln count
    vulns = set()
    vulns.update(results["shodan_free"].get("vulns", []))
    if results["shodan"].get("vulns"):
        vulns.update(results["shodan"]["vulns"])

    results["known_vulns"] = sorted(vulns)
    results["vuln_count"] = len(vulns)

    return results
