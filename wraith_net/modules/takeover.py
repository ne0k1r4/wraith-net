"""
wraith_net/modules/takeover.py — Subdomain Takeover Detection
Checks 30 known service fingerprints for dangling CNAMEs.
"""

import re
import socket
import urllib.request
import urllib.error
import json
from wraith_net.utils.helpers import normalize_domain, rate_limit, http_get
from wraith_net.core.config import HTTP_TIMEOUT

# ── 30 service fingerprints ───────────────────────────────────────────────────

FINGERPRINTS = {
    "GitHub Pages":   (re.compile(r"github\.io", re.I),
                       "There isn't a GitHub Pages site here"),
    "Heroku":         (re.compile(r"heroku\.com|herokudns\.com", re.I),
                       "No such app"),
    "Netlify":        (re.compile(r"netlify\.app|netlify\.com", re.I),
                       "Not Found - Request ID"),
    "AWS S3":         (re.compile(r"s3\.amazonaws\.com|s3-website", re.I),
                       "NoSuchBucket"),
    "AWS CloudFront": (re.compile(r"cloudfront\.net", re.I),
                       "ERROR: The request could not be satisfied"),
    "Azure":          (re.compile(r"azurewebsites\.net|azure\.com|cloudapp\.net", re.I),
                       "404 Web Site not found"),
    "Fastly":         (re.compile(r"fastly\.net", re.I),
                       "Fastly error: unknown domain"),
    "Ghost":          (re.compile(r"ghost\.io", re.I),
                       "The thing you were looking for is no longer here"),
    "Tumblr":         (re.compile(r"tumblr\.com", re.I),
                       "There's nothing here"),
    "Shopify":        (re.compile(r"myshopify\.com", re.I),
                       "Sorry, this shop is currently unavailable"),
    "Webflow":        (re.compile(r"webflow\.io", re.I),
                       "The page you are looking for doesn't exist"),
    "Surge.sh":       (re.compile(r"surge\.sh", re.I),
                       "project not found"),
    "Zendesk":        (re.compile(r"zendesk\.com", re.I),
                       "Help Center Closed"),
    "Freshdesk":      (re.compile(r"freshdesk\.com", re.I),
                       "May be this is still fresh"),
    "HubSpot":        (re.compile(r"hubspot\.net|hs-sites\.com", re.I),
                       "Domain not found"),
    "Intercom":       (re.compile(r"intercom\.io", re.I),
                       "This page is reserved for artistic"),
    "Unbounce":       (re.compile(r"unbouncepages\.com", re.I),
                       "The requested URL was not found"),
    "Readme.io":      (re.compile(r"readme\.io", re.I),
                       "Project doesnt exist"),
    "Bitbucket":      (re.compile(r"bitbucket\.io", re.I),
                       "Repository not found"),
    "Squarespace":    (re.compile(r"squarespace\.com", re.I),
                       "No Such Account"),
    "Strikingly":     (re.compile(r"strikingly\.com", re.I),
                       "But if you're looking to build your own"),
    "Fly.io":         (re.compile(r"fly\.dev|fly\.io", re.I),
                       "404 - Not Found"),
    "Render":         (re.compile(r"onrender\.com", re.I),
                       "Service not found"),
    "Vercel":         (re.compile(r"vercel\.app", re.I),
                       "The deployment could not be found"),
    "Firebase":       (re.compile(r"firebaseapp\.com|web\.app", re.I),
                       "Firebase App Not Found"),
    "WP Engine":      (re.compile(r"wpengine\.com", re.I),
                       "The site you were looking for couldn't be found"),
    "Pantheon":       (re.compile(r"pantheonsite\.io", re.I),
                       "404 error unknown site"),
    "Cargo":          (re.compile(r"cargocollective\.com", re.I),
                       "404 Not Found"),
    "Kinsta":         (re.compile(r"kinsta\.cloud", re.I),
                       "No Site For Domain"),
    "Acquia":         (re.compile(r"acquia-sites\.com", re.I),
                       "If you are an Acquia Cloud customer"),
}


# ── CNAME lookup via Google DNS ───────────────────────────────────────────────

def _get_cname(domain: str) -> str:
    try:
        url = f"https://dns.google/resolve?name={domain}&type=CNAME"
        req = urllib.request.Request(
            url, headers={"User-Agent": "WRAITH-NET/1.0"}
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = json.loads(r.read().decode())
        for ans in data.get("Answer", []):
            if ans.get("type") == 5:
                return ans.get("data", "").rstrip(".")
    except Exception:
        pass
    return ""


def _fetch_body(domain: str) -> str:
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{domain}",
                headers={"User-Agent": "WRAITH-NET/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.read(4096).decode("utf-8", "replace")
        except Exception:
            continue
    return ""


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, subdomains: list = None, progress_cb=None) -> dict:
    """
    Check subdomains for takeover vulnerabilities.
    Uses CNAME dangling + body fingerprinting against 30 known services.
    """
    domain = normalize_domain(target)
    vulnerable = []
    possible = []
    checked = 0

    if not subdomains:
        # Probe common subdomains
        wordlist = [
            "www", "mail", "dev", "staging", "test", "api", "cdn", "static",
            "assets", "media", "app", "dashboard", "portal", "beta", "shop",
            "store", "blog", "docs", "support", "help", "status", "git",
            "admin", "demo", "preview", "old", "legacy", "vpn", "remote",
        ]
        subdomains = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                subdomains.append(fqdn)
            except socket.gaierror:
                cname = _get_cname(fqdn)
                if cname:
                    subdomains.append(fqdn)
            rate_limit(0.05)

    if progress_cb:
        progress_cb(f"takeover [checking {len(subdomains)} subdomains]")

    for fqdn in subdomains:
        cname = _get_cname(fqdn)
        if not cname:
            continue
        checked += 1

        for service, (cname_pat, body_sig) in FINGERPRINTS.items():
            if cname_pat.search(cname):
                body = _fetch_body(fqdn)
                if body_sig.lower() in body.lower():
                    vulnerable.append({
                        "fqdn": fqdn,
                        "service": service,
                        "cname": cname,
                        "fingerprint": body_sig,
                        "confirmed": True,
                    })
                else:
                    possible.append({
                        "fqdn": fqdn,
                        "service": service,
                        "cname": cname,
                        "confirmed": False,
                    })
                break
        rate_limit(0.2)

    return {
        "domain": domain,
        "subdomains_checked": checked,
        "vulnerable": vulnerable,
        "possible": possible,
        "vuln_count": len(vulnerable),
        "possible_count": len(possible),
        "has_vulns": len(vulnerable) > 0,
    }
