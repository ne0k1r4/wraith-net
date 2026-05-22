"""
wraith_net/modules/risk_score.py — Aggregate Risk Scoring Engine
Combines all module findings into a single risk assessment.
"""

from wraith_net.utils.helpers import normalize_domain


RISK_LEVELS = {
    0:  ("A", "CLEAN",    "#30d158"),
    1:  ("B", "LOW",      "#ffd60a"),
    2:  ("C", "MEDIUM",   "#ff9f0a"),
    3:  ("D", "HIGH",     "#ff6b35"),
    4:  ("F", "CRITICAL", "#ff2d55"),
}


def _score_subdomains(data: dict) -> tuple[int, list]:
    issues = []
    score = 0
    count = data.get("count", 0)
    if count > 50:
        score += 1
        issues.append(f"Large attack surface — {count} subdomains exposed")
    return score, issues


def _score_ports(data: dict) -> tuple[int, list]:
    issues = []
    score = 0
    sensitive = data.get("sensitive_ports", [])
    open_ports = data.get("open_ports", [])

    CRITICAL_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
    for p in open_ports:
        port = p.get("port", 0)
        if port in CRITICAL_PORTS:
            score += 2
            issues.append(f"Sensitive port {port}/{p.get('service','?')} exposed")

    if len(open_ports) > 20:
        score += 1
        issues.append(f"Large open port count ({len(open_ports)})")

    return min(score, 4), issues


def _score_techstack(data: dict) -> tuple[int, list]:
    issues = []
    score = 0
    techs = data.get("technologies", [])
    versions = data.get("versions", {})
    waf = data.get("waf")

    if not waf:
        score += 1
        issues.append("No WAF/CDN detected — direct access to origin")

    # Outdated tech signals
    OUTDATED_SIGNALS = ["PHP 5", "PHP 7.0", "PHP 7.1", "Apache/2.2",
                        "nginx/1.0", "IIS/6", "IIS/7", "jQuery 1.", "jQuery 2."]
    ssl = data.get("ssl", {})
    if ssl:
        expire = ssl.get("expire", "")
        if expire:
            try:
                from datetime import datetime
                exp_dt = datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z")
                if (exp_dt - datetime.utcnow()).days < 30:
                    score += 2
                    issues.append(f"SSL certificate expires soon: {expire}")
            except Exception:
                pass

    for sig in OUTDATED_SIGNALS:
        server = data.get("server", "")
        if sig.lower() in server.lower():
            score += 1
            issues.append(f"Potentially outdated software: {server}")
            break

    return min(score, 3), issues


def _score_dns_security(data: dict) -> tuple[int, list]:
    issues = []
    score = 0

    spf = data.get("spf", {})
    dmarc = data.get("dmarc", {})
    dkim = data.get("dkim", {})
    dnssec = data.get("dnssec", {})

    if not spf.get("present"):
        score += 2
        issues.append("No SPF record — domain spoofing possible")
    elif spf.get("score", 0) == 0:
        score += 1
        issues.extend(spf.get("issues", []))

    if not dmarc.get("present"):
        score += 2
        issues.append("No DMARC record — phishing using domain undetected")
    elif dmarc.get("score", 0) < 2:
        score += 1
        issues.extend(dmarc.get("issues", []))

    if not dkim.get("present"):
        score += 1
        issues.append("No DKIM found — email integrity unverified")

    if not dnssec.get("enabled"):
        score += 1
        issues.append("DNSSEC not enabled")

    return min(score, 4), issues


def _score_breach(data: dict) -> tuple[int, list]:
    issues = []
    score = 0
    breaches = data.get("hibp_breaches", [])
    pastes = data.get("pastes", [])

    if breaches:
        total_pwned = sum(b.get("pwn_count", 0) for b in breaches)
        score += min(len(breaches), 3)
        issues.append(f"{len(breaches)} breach(es) found — {total_pwned:,} accounts compromised")
        for b in breaches[:3]:
            classes = ", ".join(b.get("data_classes", [])[:3])
            issues.append(f"  Breach: {b.get('name')} ({b.get('date', '?')}) — {classes}")

    if pastes:
        score += 1
        issues.append(f"{len(pastes)} paste(s) found — possible credential exposure")

    return min(score, 4), issues


def _score_shodan(data: dict) -> tuple[int, list]:
    issues = []
    score = 0

    free = data.get("shodan_free", {})
    shodan = data.get("shodan", {})

    vulns = set(free.get("vulns", []))
    if shodan.get("vulns"):
        vulns.update(shodan["vulns"])

    CRITICAL_CVES = {"CVE-2021-44228", "CVE-2017-0144", "CVE-2019-0708",
                     "CVE-2021-26855", "CVE-2022-26134", "CVE-2021-34473"}

    if vulns:
        score += min(len(vulns), 4)
        issues.append(f"{len(vulns)} known CVE(s) from Shodan")
        for cve in list(vulns)[:5]:
            if cve in CRITICAL_CVES:
                issues.append(f"  CRITICAL: {cve}")
            else:
                issues.append(f"  CVE: {cve}")

    tags = free.get("tags", []) + shodan.get("tags", [])
    if "honeypot" in tags:
        issues.append("Shodan tags: possible honeypot")
    if "tor" in tags:
        score += 1
        issues.append("Shodan tags: TOR exit node")
    if "vpn" in tags:
        issues.append("Shodan tags: VPN endpoint")

    return min(score, 4), issues


def _score_takeover(data: dict) -> tuple[int, list]:
    issues = []
    score = 0
    vuln_count = data.get("vuln_count", 0)
    possible_count = data.get("possible_count", 0)

    if vuln_count:
        score += 4
        for v in data.get("vulnerable", []):
            issues.append(f"CONFIRMED takeover: {v['fqdn']} → {v['service']}")
    if possible_count:
        score += 1
        for v in data.get("possible", [])[:3]:
            issues.append(f"Possible takeover: {v['fqdn']} → {v['service']}")

    return min(score, 4), issues


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, all_results: dict) -> dict:
    """
    Aggregate all module results into a risk score.
    Returns grade (A-F), level, score, and all findings.
    """
    domain = normalize_domain(target)
    total_score = 0
    all_issues = []
    breakdown = {}

    scorers = [
        ("subdomains",   _score_subdomains,   all_results.get("subdomains", {})),
        ("ports",        _score_ports,         all_results.get("ports", {})),
        ("techstack",    _score_techstack,     all_results.get("techstack", {})),
        ("dns_security", _score_dns_security,  all_results.get("dns_security", {})),
        ("breach",       _score_breach,        all_results.get("breach", {})),
        ("shodan",       _score_shodan,        all_results.get("shodan", {})),
        ("takeover",     _score_takeover,      all_results.get("takeover", {})),
    ]

    for module_name, scorer_fn, data in scorers:
        if data:
            score, issues = scorer_fn(data)
            total_score += score
            all_issues.extend(issues)
            breakdown[module_name] = {"score": score, "issues": issues}

    # Normalize to 0-4 scale
    max_possible = len([s for s in scorers if s[2]]) * 4
    normalized = int((total_score / max_possible * 4)) if max_possible else 0
    normalized = min(normalized, 4)

    grade, level, color = RISK_LEVELS[normalized]

    return {
        "domain": domain,
        "grade": grade,
        "level": level,
        "color": color,
        "raw_score": total_score,
        "max_score": max_possible,
        "issues": all_issues,
        "issue_count": len(all_issues),
        "breakdown": breakdown,
    }
