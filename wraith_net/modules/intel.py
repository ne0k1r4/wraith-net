"""
wraith_net/modules/intel.py — Advanced Threat Intelligence Correlation
ASN/BGP analysis · IP reputation · related infrastructure · historical data
"""

import re
import socket
import urllib.request
import urllib.error
import json
from wraith_net.utils.helpers import normalize_domain, rate_limit, http_get_json
from wraith_net.core.config import HTTP_TIMEOUT, VIRUSTOTAL_API_KEY, GITHUB_API_KEY


# ── ASN / BGP Intelligence ────────────────────────────────────────────────────

def _asn_info(ip: str) -> dict:
    """Get ASN, org, country, prefix from ipinfo.io (free tier)."""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        return {
            "ip":       data.get("ip"),
            "hostname": data.get("hostname"),
            "org":      data.get("org"),
            "asn":      data.get("org", "").split()[0] if data.get("org") else None,
            "country":  data.get("country"),
            "city":     data.get("city"),
            "region":   data.get("region"),
            "prefix":   data.get("prefix"),
            "timezone": data.get("timezone"),
        }
    except Exception:
        return {}


def _bgp_prefix_peers(asn: str) -> dict:
    """Get BGP prefix and peer info from bgpview.io (free API)."""
    if not asn or not asn.startswith("AS"):
        return {}
    asn_num = asn.replace("AS", "")
    try:
        url = f"https://api.bgpview.io/asn/{asn_num}"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        d = data.get("data", {})
        return {
            "asn":         asn,
            "name":        d.get("name"),
            "description": d.get("description_short"),
            "country":     d.get("country_code"),
            "website":     d.get("website"),
            "abuse_email": (d.get("abuse_contacts") or [{}])[0].get("email") if d.get("abuse_contacts") else None,
            "rir":         d.get("rir_allocation", {}).get("rir_name"),
        }
    except Exception:
        return {}


def _asn_prefixes(asn: str) -> list:
    """Get all IP prefixes announced by an ASN."""
    if not asn:
        return []
    asn_num = asn.replace("AS", "")
    try:
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        prefixes = []
        for p in data.get("data", {}).get("ipv4_prefixes", [])[:20]:
            prefixes.append({
                "prefix": p.get("prefix"),
                "name":   p.get("name"),
                "description": p.get("description"),
            })
        return prefixes
    except Exception:
        return []


# ── Related Infrastructure ────────────────────────────────────────────────────

def _reverse_ip(ip: str) -> list:
    """Find other domains hosted on the same IP via HackerTarget."""
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            body = r.read().decode("utf-8", "replace")
        if "error" in body.lower() or "no records" in body.lower():
            return []
        return [d.strip() for d in body.strip().splitlines() if d.strip()][:50]
    except Exception:
        return []


def _dns_history(domain: str) -> list:
    """Get historical DNS data from SecurityTrails-compatible free sources."""
    results = []
    # Try completedns.com (free historical data)
    try:
        url = f"https://completedns.com/dns-history/api/fetch?domain={domain}&type=A"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        if isinstance(data, list):
            for entry in data[:10]:
                results.append({
                    "ip":   entry.get("ip"),
                    "date": entry.get("date"),
                })
    except Exception:
        pass
    return results


def _google_transparency(domain: str) -> list:
    """Get SSL certs from Google Certificate Transparency via crt.sh."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        seen = set()
        certs = []
        for entry in data[:30]:
            name_val = entry.get("name_value", "")
            issuer   = entry.get("issuer_name", "")
            date     = entry.get("not_before", "")
            for name in name_val.splitlines():
                name = name.strip().lstrip("*.")
                if name not in seen and domain in name:
                    seen.add(name)
                    certs.append({
                        "name":   name,
                        "issuer": issuer[:40],
                        "date":   date[:10],
                    })
        return certs
    except Exception:
        return []


# ── IP Reputation ─────────────────────────────────────────────────────────────

def _ip_reputation_offline(ip: str) -> dict:
    """Offline IP reputation checks — known malicious ranges."""
    MALICIOUS_RANGES = [
        (re.compile(r"^185\.220\."), "Known TOR exit node range"),
        (re.compile(r"^5\.188\."),   "Known spam/abuse range"),
        (re.compile(r"^194\.165\."), "Known C2/malware range"),
        (re.compile(r"^45\.95\."),   "Known scanning range"),
        (re.compile(r"^91\.108\."),  "Telegram-associated abuse"),
        (re.compile(r"^198\.54\."),  "Known spam range"),
        (re.compile(r"^159\.65\."),  "DigitalOcean scanning range"),
    ]
    for pattern, reason in MALICIOUS_RANGES:
        if pattern.match(ip):
            return {"malicious": True, "reason": reason, "source": "offline"}
    return {"malicious": False, "reason": "Not in offline blocklist", "source": "offline"}


def _check_tor_exit(ip: str) -> bool:
    """Check if IP is a known TOR exit node via dan.me.uk."""
    try:
        # Reverse octets for DNS lookup
        octets = ip.split(".")
        reversed_ip = ".".join(reversed(octets))
        lookup = f"{reversed_ip}.dnsel.torproject.org"
        socket.gethostbyname(lookup)
        return True  # Resolves = TOR exit node
    except socket.gaierror:
        return False
    except Exception:
        return False


def _virustotal_domain(domain: str, api_key: str = None) -> dict:
    """VirusTotal domain lookup (requires free API key)."""
    if not api_key:
        return {}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = urllib.request.Request(url, headers={
            "x-apikey": api_key,
            "User-Agent": "WRAITH-NET/1.0"
        })
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        return {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "reputation":  attrs.get("reputation", 0),
            "categories":  attrs.get("categories", {}),
            "last_analysis": attrs.get("last_analysis_date"),
        }
    except Exception:
        return {}


# ── GitHub Dorking ────────────────────────────────────────────────────────────

def _github_dork(domain: str, api_key: str = None) -> list:
    """
    Search GitHub for exposed secrets, config files, and credentials
    mentioning the target domain.
    Returns list of findings with repo, file, and snippet.
    """
    headers = {"User-Agent": "WRAITH-NET/1.0", "Accept": "application/vnd.github+json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    DORKS = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" token',
        f'"{domain}" credential',
    ]

    findings = []
    seen_repos = set()

    for dork in DORKS:
        try:
            encoded = urllib.parse.quote(dork) if hasattr(urllib, 'parse') else dork.replace(" ", "+")
            import urllib.parse
            encoded = urllib.parse.quote(dork)
            url = f"https://api.github.com/search/code?q={encoded}&per_page=5"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                data = json.loads(r.read().decode())

            for item in data.get("items", []):
                repo = item.get("repository", {}).get("full_name", "")
                if repo in seen_repos:
                    continue
                seen_repos.add(repo)
                findings.append({
                    "repo":     repo,
                    "file":     item.get("name"),
                    "path":     item.get("path"),
                    "url":      item.get("html_url"),
                    "query":    dork,
                    "private":  item.get("repository", {}).get("private", False),
                })
        except Exception:
            pass
        rate_limit(2.0)  # GitHub rate limiting

    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, config: dict = None, progress_cb=None) -> dict:
    """
    Full threat intelligence correlation for a domain.
    """
    import urllib.parse
    domain = normalize_domain(target)
    cfg    = config or {}
    vt_key = cfg.get("virustotal_api_key") or VIRUSTOTAL_API_KEY
    gh_key = cfg.get("github_api_key") or GITHUB_API_KEY

    result = {
        "domain":        domain,
        "ips":           [],
        "asn_info":      [],
        "bgp_info":      [],
        "prefixes":      [],
        "reverse_ip":    [],
        "ct_certs":      [],
        "dns_history":   [],
        "ip_reputation": [],
        "tor_exits":     [],
        "virustotal":    {},
        "github_dorks":  [],
        "issues":        [],
    }

    # Resolve domain to IPs
    if progress_cb:
        progress_cb("intel [DNS resolution]")
    try:
        ips = list(set(socket.gethostbyname_ex(domain)[2]))
        result["ips"] = ips
    except Exception:
        ips = []

    # ASN info for each IP
    if progress_cb:
        progress_cb("intel [ASN/BGP lookup]")
    for ip in ips[:3]:
        asn_data = _asn_info(ip)
        if asn_data:
            result["asn_info"].append(asn_data)
            asn = asn_data.get("asn")
            if asn:
                bgp = _bgp_prefix_peers(asn)
                if bgp:
                    result["bgp_info"].append(bgp)
                prefixes = _asn_prefixes(asn)
                result["prefixes"].extend(prefixes[:5])
        rate_limit(0.5)

    # Reverse IP — co-hosted domains
    if progress_cb:
        progress_cb("intel [reverse IP lookup]")
    for ip in ips[:2]:
        rev = _reverse_ip(ip)
        if rev:
            result["reverse_ip"].extend(rev)
            if len(rev) > 10:
                result["issues"].append(
                    f"Shared hosting detected — {len(rev)} domains on {ip}"
                )
        rate_limit(0.5)

    # Certificate transparency
    if progress_cb:
        progress_cb("intel [certificate transparency]")
    result["ct_certs"] = _google_transparency(domain)

    # IP reputation
    if progress_cb:
        progress_cb("intel [IP reputation]")
    for ip in ips[:3]:
        rep = _ip_reputation_offline(ip)
        if rep.get("malicious"):
            result["ip_reputation"].append({"ip": ip, **rep})
            result["issues"].append(f"Malicious IP range: {ip} — {rep['reason']}")
        is_tor = _check_tor_exit(ip)
        if is_tor:
            result["tor_exits"].append(ip)
            result["issues"].append(f"TOR exit node: {ip}")
        rate_limit(0.3)

    # VirusTotal
    if vt_key and progress_cb:
        progress_cb("intel [VirusTotal]")
    if vt_key:
        result["virustotal"] = _virustotal_domain(domain, vt_key)
        vt = result["virustotal"]
        if vt.get("malicious", 0) >= 3:
            result["issues"].append(
                f"VirusTotal: {vt['malicious']} engines flag domain as malicious"
            )

    # GitHub dorking
    if progress_cb:
        progress_cb("intel [GitHub dorks]")
    result["github_dorks"] = _github_dork(domain, gh_key)
    if result["github_dorks"]:
        result["issues"].append(
            f"GitHub: {len(result['github_dorks'])} public repo(s) expose domain-related data"
        )

    return result
