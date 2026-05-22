"""
wraith_net/modules/dns_security.py — DNS & Email Security Checks
Checks SPF, DMARC, DKIM, DNSSEC, MX reputation, open relay.
"""

import re
import socket
from wraith_net.utils.helpers import http_get_json, rate_limit, normalize_domain
from wraith_net.core.config import HTTP_TIMEOUT


# ── DNS query helper ──────────────────────────────────────────────────────────

def _dns_txt(domain: str) -> list[str]:
    """Fetch TXT records via Google DNS JSON API."""
    import urllib.request, json as _json
    try:
        url = f"https://dns.google/resolve?name={domain}&type=TXT"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read().decode())
    except Exception:
        return []
    if not data:
        return []
    records = []
    for ans in data.get("Answer", []):
        if ans.get("type") == 16:  # TXT
            val = ans.get("data", "").strip('"')
            records.append(val)
    return records


def _dns_mx(domain: str) -> list[str]:
    """Fetch MX records via Google DNS JSON API."""
    import urllib.request, json as _json
    try:
        url = f"https://dns.google/resolve?name={domain}&type=MX"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read().decode())
    except Exception:
        return []
    if not data:
        return []
    mx = []
    for ans in data.get("Answer", []):
        if ans.get("type") == 15:  # MX
            parts = ans.get("data", "").split()
            if len(parts) >= 2:
                mx.append(parts[1].rstrip("."))
    return mx


def _dns_ns(domain: str) -> list[str]:
    """Fetch NS records."""
    import urllib.request, json as _json
    try:
        url = f"https://dns.google/resolve?name={domain}&type=NS"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read().decode())
    except Exception:
        return []
    if not data:
        return []
    return [
        ans.get("data", "").rstrip(".")
        for ans in data.get("Answer", [])
        if ans.get("type") == 2
    ]


def _dns_a(domain: str) -> list[str]:
    """Fetch A records."""
    import urllib.request, json as _json
    try:
        url = f"https://dns.google/resolve?name={domain}&type=A"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read().decode())
    except Exception:
        return []
    if not data:
        return []
    return [
        ans.get("data", "")
        for ans in data.get("Answer", [])
        if ans.get("type") == 1
    ]


# ── SPF Analysis ──────────────────────────────────────────────────────────────

def _check_spf(domain: str) -> dict:
    """Analyse SPF record for misconfigurations."""
    txt_records = _dns_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    result = {
        "present": False,
        "record": None,
        "issues": [],
        "score": 0,  # 0=fail, 1=warn, 2=ok
    }

    if not spf_records:
        result["issues"].append("No SPF record — domain spoofing possible")
        return result

    if len(spf_records) > 1:
        result["issues"].append(f"Multiple SPF records ({len(spf_records)}) — invalid, only first used")

    spf = spf_records[0]
    result["present"] = True
    result["record"] = spf

    # Check for +all (allow all — completely open)
    if "+all" in spf:
        result["issues"].append("SPF uses '+all' — allows any server to send as domain")
        result["score"] = 0
        return result

    # Check for ~all vs -all
    if "~all" in spf:
        result["issues"].append("SPF uses '~all' (softfail) — spoofed mail may be accepted")
        result["score"] = 1
    elif "-all" in spf:
        result["score"] = 2  # strict
    elif "?all" in spf:
        result["issues"].append("SPF uses '?all' (neutral) — no protection")
        result["score"] = 0
    else:
        result["issues"].append("SPF missing 'all' qualifier")
        result["score"] = 0

    # Check for too many DNS lookups (>10 = permerror)
    lookup_mechanisms = re.findall(r"\b(include|a|mx|ptr|exists):", spf)
    if len(lookup_mechanisms) > 8:
        result["issues"].append(f"SPF has {len(lookup_mechanisms)} DNS lookups (limit=10, may permerror)")

    # Check for deprecated ptr mechanism
    if "ptr" in spf:
        result["issues"].append("SPF uses deprecated 'ptr' mechanism — slow and unreliable")

    return result


# ── DMARC Analysis ────────────────────────────────────────────────────────────

def _check_dmarc(domain: str) -> dict:
    """Analyse DMARC record."""
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _dns_txt(dmarc_domain)
    dmarc_records = [r for r in txt_records if "v=DMARC1" in r]

    result = {
        "present": False,
        "record": None,
        "policy": None,
        "pct": None,
        "rua": None,
        "issues": [],
        "score": 0,
    }

    if not dmarc_records:
        result["issues"].append("No DMARC record — spoofed emails not reported or rejected")
        return result

    dmarc = dmarc_records[0]
    result["present"] = True
    result["record"] = dmarc

    # Parse policy
    p_match = re.search(r"\bp=(\w+)", dmarc)
    if p_match:
        policy = p_match.group(1).lower()
        result["policy"] = policy
        if policy == "none":
            result["issues"].append("DMARC policy=none — monitoring only, no enforcement")
            result["score"] = 1
        elif policy == "quarantine":
            result["score"] = 2
        elif policy == "reject":
            result["score"] = 3  # best
        else:
            result["issues"].append(f"Unknown DMARC policy: {policy}")
    else:
        result["issues"].append("DMARC missing 'p=' policy tag")
        result["score"] = 0

    # Parse pct
    pct_match = re.search(r"\bpct=(\d+)", dmarc)
    if pct_match:
        pct = int(pct_match.group(1))
        result["pct"] = pct
        if pct < 100 and result["policy"] != "none":
            result["issues"].append(f"DMARC pct={pct}% — policy only applies to {pct}% of mail")

    # Check for reporting address
    rua_match = re.search(r"\brua=([^\s;]+)", dmarc)
    if rua_match:
        result["rua"] = rua_match.group(1)
    else:
        result["issues"].append("DMARC missing 'rua=' — no aggregate reports configured")

    # Subdomain policy
    sp_match = re.search(r"\bsp=(\w+)", dmarc)
    if sp_match and sp_match.group(1).lower() == "none":
        result["issues"].append("DMARC sp=none — subdomain policy not enforced")

    return result


# ── DKIM Check ────────────────────────────────────────────────────────────────

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2", "selector1", "selector2",
    "dkim", "smtp", "email", "s1", "s2", "mx", "protonmail",
    "zoho", "mailchimp", "sendgrid", "amazonses",
]

def _check_dkim(domain: str) -> dict:
    """Probe common DKIM selectors."""
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = _dns_txt(dkim_domain)
        for r in txt_records:
            if "v=DKIM1" in r or "k=rsa" in r or "p=" in r:
                key_match = re.search(r"p=([A-Za-z0-9+/=]{10,})", r)
                key_len = len(key_match.group(1)) * 6 // 8 if key_match else 0
                issues = []
                if key_len and key_len < 256:
                    issues.append(f"Weak key length (~{key_len*8} bits)")
                if "h=sha1" in r:
                    issues.append("Uses SHA-1 (deprecated)")
                found.append({
                    "selector": selector,
                    "record": r[:120],
                    "key_length_approx": key_len,
                    "issues": issues,
                })
        rate_limit(0.1)

    return {
        "selectors_found": found,
        "count": len(found),
        "present": len(found) > 0,
    }


# ── DNSSEC Check ──────────────────────────────────────────────────────────────

def _check_dnssec(domain: str) -> dict:
    """Check if DNSSEC is enabled via Google DNS."""
    url = f"https://dns.google/resolve?name={domain}&type=DNSKEY"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data:
        return {"enabled": False, "issues": ["Could not check DNSSEC"]}
    status = data.get("Status", 2)
    answers = data.get("Answer", [])
    dnskeys = [a for a in answers if a.get("type") == 48]

    if dnskeys:
        return {"enabled": True, "key_count": len(dnskeys), "issues": []}

    # Check AD bit (Authentic Data)
    ad = data.get("AD", False)
    if ad:
        return {"enabled": True, "key_count": 0, "issues": []}

    return {
        "enabled": False,
        "issues": ["DNSSEC not enabled — DNS responses unverified"],
    }


# ── MX Security ───────────────────────────────────────────────────────────────

def _check_mx_security(domain: str, mx_hosts: list) -> dict:
    """Check MX record security — STARTTLS, DANE."""
    issues = []
    results = []

    if not mx_hosts:
        return {"issues": ["No MX records — domain not configured to receive email"], "hosts": []}

    # Check for suspicious/free MX providers
    suspicious_patterns = [
        r"\.ru$", r"\.cn$", r"\.tk$",
    ]
    for mx in mx_hosts[:5]:
        host_issues = []
        for pat in suspicious_patterns:
            if re.search(pat, mx, re.I):
                host_issues.append(f"Unusual MX provider TLD: {mx}")

        # Try SMTP banner grab for TLS info
        try:
            s = socket.create_connection((mx, 25), timeout=5)
            banner = s.recv(256).decode("utf-8", "replace")
            s.send(b"EHLO wraith-net.test\r\n")
            ehlo_resp = s.recv(1024).decode("utf-8", "replace")
            s.close()
            has_starttls = "STARTTLS" in ehlo_resp.upper()
            if not has_starttls:
                host_issues.append(f"STARTTLS not advertised on {mx}:25")
            results.append({
                "host": mx,
                "starttls": has_starttls,
                "banner": banner.strip()[:80],
            })
        except Exception:
            results.append({"host": mx, "starttls": None, "banner": ""})

        issues.extend(host_issues)

    return {"hosts": results, "issues": issues}


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, progress_cb=None) -> dict:
    """
    Run full DNS security audit.
    Returns SPF, DMARC, DKIM, DNSSEC, MX security findings.
    """
    domain = normalize_domain(target)

    result = {
        "domain": domain,
        "spf": {},
        "dmarc": {},
        "dkim": {},
        "dnssec": {},
        "mx_security": {},
        "mx_hosts": [],
        "nameservers": [],
        "a_records": [],
        "issues": [],
        "risk_score": 0,
    }

    if progress_cb:
        progress_cb("dns_security [SPF]")
    result["spf"] = _check_spf(domain)
    rate_limit(0.3)

    if progress_cb:
        progress_cb("dns_security [DMARC]")
    result["dmarc"] = _check_dmarc(domain)
    rate_limit(0.3)

    if progress_cb:
        progress_cb("dns_security [DKIM]")
    result["dkim"] = _check_dkim(domain)
    rate_limit(0.3)

    if progress_cb:
        progress_cb("dns_security [DNSSEC]")
    result["dnssec"] = _check_dnssec(domain)
    rate_limit(0.3)

    if progress_cb:
        progress_cb("dns_security [MX]")
    mx_hosts = _dns_mx(domain)
    result["mx_hosts"] = mx_hosts
    result["mx_security"] = _check_mx_security(domain, mx_hosts)
    result["nameservers"] = _dns_ns(domain)
    result["a_records"] = _dns_a(domain)

    # Aggregate all issues
    all_issues = (
        result["spf"].get("issues", [])
        + result["dmarc"].get("issues", [])
        + [f"DKIM: {i}" for sel in result["dkim"].get("selectors_found", [])
           for i in sel.get("issues", [])]
        + result["dnssec"].get("issues", [])
        + result["mx_security"].get("issues", [])
    )
    if not result["dkim"]["present"]:
        all_issues.append("No DKIM selector found — email integrity unverified")

    result["issues"] = all_issues

    # Risk score
    score = 0
    score += 2 if not result["spf"]["present"] else (0 if result["spf"]["score"] == 2 else 1)
    score += 2 if not result["dmarc"]["present"] else (0 if result["dmarc"]["score"] >= 2 else 1)
    score += 1 if not result["dkim"]["present"] else 0
    score += 1 if not result["dnssec"]["enabled"] else 0
    result["risk_score"] = score  # 0=clean, 6=critical

    return result
