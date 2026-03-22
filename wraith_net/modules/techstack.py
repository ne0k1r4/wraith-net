"""
wraith_net/modules/techstack.py — Technology fingerprinting
Analyzes HTTP headers, body patterns, cookies, and meta tags.
"""

import re
from typing import Optional
from wraith_net.utils.helpers import http_get_response, normalize_domain
from wraith_net.core.config import TECH_SIGNATURES, HTTP_TIMEOUT


# ── SSL/TLS cert info ─────────────────────────────────────────────────────────

def _ssl_info(domain: str) -> dict:
    try:
        import ssl, socket
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(HTTP_TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "expire": cert.get("notAfter", ""),
                "san": [v for _, v in cert.get("subjectAltName", [])],
                "version": cert.get("version", ""),
            }
    except Exception:
        return {}


# ── Header-based detection ────────────────────────────────────────────────────

def _headers_fingerprint(headers: dict) -> list[str]:
    detected = []
    norm = {k.lower(): v.lower() for k, v in headers.items()}

    sig_headers = TECH_SIGNATURES["headers"]
    for header_name, keywords in sig_headers.items():
        hval = norm.get(header_name.lower(), "")
        if keywords == {"": ""}:  # presence-only check
            for k, tech in keywords.items():
                if hval or header_name.lower() in norm:
                    detected.append(tech)
        else:
            for kw, tech in keywords.items():
                if kw and kw in hval:
                    detected.append(tech)

    # Extra header checks
    if "cf-ray" in norm:
        detected.append("Cloudflare")
    if "x-shopify" in " ".join(norm.keys()):
        detected.append("Shopify")
    if "x-wp-nonce" in norm or "x-pingback" in norm:
        detected.append("WordPress")
    if "x-drupal" in " ".join(norm.keys()):
        detected.append("Drupal")
    if "x-aspnet" in " ".join(norm.keys()):
        detected.append("ASP.NET")

    return list(set(detected))


# ── Body-based detection ──────────────────────────────────────────────────────

def _body_fingerprint(body: str) -> list[str]:
    detected = []
    sig_body = TECH_SIGNATURES["body"]
    for pattern, tech in sig_body.items():
        if re.search(pattern, body, re.IGNORECASE):
            detected.append(tech)
    return list(set(detected))


# ── Cookie-based detection ────────────────────────────────────────────────────

def _cookie_fingerprint(headers: dict) -> list[str]:
    detected = []
    cookies = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
    cookie_sigs = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java/JSP",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "wp-": "WordPress",
        "_shopify": "Shopify",
        "Drupal": "Drupal",
    }
    for sig, tech in cookie_sigs.items():
        if sig.lower() in cookies.lower():
            detected.append(tech)
    return list(set(detected))


# ── CMS version extraction ────────────────────────────────────────────────────

def _extract_versions(body: str, tech_list: list) -> dict:
    versions = {}
    if "WordPress" in tech_list:
        m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', body, re.IGNORECASE)
        if m:
            versions["WordPress"] = m.group(1)
    if "Drupal" in tech_list:
        m = re.search(r'Drupal ([0-9.]+)', body, re.IGNORECASE)
        if m:
            versions["Drupal"] = m.group(1)
    if "jQuery" in tech_list:
        m = re.search(r'jquery[/-]([0-9.]+)(?:\.min)?\.js', body, re.IGNORECASE)
        if m:
            versions["jQuery"] = m.group(1)
    return versions


# ── WAF detection ─────────────────────────────────────────────────────────────

def _detect_waf(headers: dict, body: str) -> Optional[str]:
    waf_sigs = {
        "Cloudflare":   ["cf-ray", "cf-cache-status", "__cfduid"],
        "AWS WAF":      ["awselb", "x-amzn-requestid"],
        "Akamai":       ["akamai-origin-hop", "x-check-cacheable"],
        "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
        "Imperva":      ["x-iinfo", "visid_incap"],
        "Barracuda":    ["barra_counter_session"],
        "F5 BIG-IP":    ["bigipserver", "f5-", "ts0"],
    }
    norm_headers = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, indicators in waf_sigs.items():
        for ind in indicators:
            if any(ind in k or ind in v for k, v in norm_headers.items()):
                return waf
    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, progress_cb=None) -> dict:
    """
    Fingerprint technologies used by the target.
    Returns: {
        "target": str,
        "technologies": list,
        "versions": dict,
        "waf": str|None,
        "ssl": dict,
        "status_code": int,
        "server": str,
        "cms": str|None,
    }
    """
    domain = normalize_domain(target)
    tech_all = []
    versions = {}
    waf = None
    ssl_data = {}
    status = None
    server = "unknown"

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        if progress_cb:
            progress_cb(f"techstack [{scheme}]")
        resp = http_get_response(url, timeout=HTTP_TIMEOUT)
        if resp is None:
            continue
        code, hdrs, body = resp
        status = code

        server = hdrs.get("Server", hdrs.get("server", "unknown"))
        waf = _detect_waf(hdrs, body)
        tech_all += _headers_fingerprint(hdrs)
        tech_all += _body_fingerprint(body)
        tech_all += _cookie_fingerprint(hdrs)
        versions.update(_extract_versions(body, tech_all))
        break

    if progress_cb:
        progress_cb("techstack [SSL]")
    ssl_data = _ssl_info(domain)

    tech_unique = list(set(tech_all))

    # Determine CMS
    cms_candidates = [t for t in tech_unique if t in ("WordPress", "Drupal", "Joomla", "Ghost", "Shopify", "Squarespace", "Wix")]
    cms = cms_candidates[0] if cms_candidates else None

    return {
        "target": domain,
        "technologies": sorted(tech_unique),
        "versions": versions,
        "waf": waf,
        "ssl": ssl_data,
        "status_code": status,
        "server": server,
        "cms": cms,
    }
