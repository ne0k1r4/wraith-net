"""
wraith_net/modules/breach.py — Breach & leaked credential lookup
Sources: HaveIBeenPwned, IntelX, LeakLookup, DeHashed (if key available)
"""

import re
from wraith_net.utils.helpers import http_get_json, http_get, rate_limit
from wraith_net.core.config import HIBP_API_KEY, INTELX_API_KEY, HTTP_TIMEOUT


# ── HaveIBeenPwned ────────────────────────────────────────────────────────────

def _hibp_domain(domain: str) -> list[dict]:
    """Check HIBP breaches for a domain (requires API key)."""
    if not HIBP_API_KEY:
        return []
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "WRAITH-NET/1.0",
    }
    data = http_get_json(url, headers=headers, timeout=HTTP_TIMEOUT)
    if not data:
        return []
    results = []
    for email, breaches in data.items():
        results.append({
            "email": email,
            "breaches": breaches,
            "count": len(breaches),
        })
    return results


def _hibp_breaches(domain: str) -> list[dict]:
    """List all known breaches associated with the domain."""
    url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
    headers = {}
    if HIBP_API_KEY:
        headers["hibp-api-key"] = HIBP_API_KEY
    data = http_get_json(url, headers=headers, timeout=HTTP_TIMEOUT)
    if not isinstance(data, list):
        return []
    return [
        {
            "name": b.get("Name"),
            "date": b.get("BreachDate"),
            "pwn_count": b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "verified": b.get("IsVerified", False),
        }
        for b in data
    ]


# ── IntelX ────────────────────────────────────────────────────────────────────

def _intelx(domain: str) -> list[dict]:
    """IntelX search for domain leaks (requires API key)."""
    if not INTELX_API_KEY:
        return []
    # Phase 1: search
    search_url = "https://2.intelx.io/intelligent/search"
    payload = f'{{"term":"{domain}","maxresults":10,"media":0,"sort":4,"terminate":[]}}'
    raw = http_get(
        search_url,
        headers={
            "x-key": INTELX_API_KEY,
            "Content-Type": "application/json",
        },
        timeout=HTTP_TIMEOUT,
    )
    if not raw:
        return []
    try:
        import json
        data = json.loads(raw.decode("utf-8", errors="replace"))
        sid = data.get("id")
    except Exception:
        return []
    if not sid:
        return []
    rate_limit(1.0)
    # Phase 2: results
    result_url = f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=10"
    rdata = http_get_json(
        result_url,
        headers={"x-key": INTELX_API_KEY},
        timeout=HTTP_TIMEOUT,
    )
    if not rdata:
        return []
    records = []
    for item in rdata.get("records", []):
        records.append({
            "name": item.get("name", ""),
            "date": item.get("date", ""),
            "type": item.get("type", ""),
            "bucket": item.get("bucket", ""),
        })
    return records


# ── LeakLookup ────────────────────────────────────────────────────────────────

def _leaklookup(domain: str) -> list[dict]:
    """LeakLookup public search (no key needed for basic)."""
    url = f"https://leak-lookup.com/api/search?type=domain_name&query={domain}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data or data.get("error"):
        return []
    results = []
    for src, entries in data.get("message", {}).items():
        if isinstance(entries, list):
            results.append({
                "source": src,
                "count": len(entries),
            })
    return results


# ── Paste search via pastebins ────────────────────────────────────────────────

def _psbdmp(domain: str) -> list[dict]:
    """psbdmp.ws — public paste search."""
    url = f"https://psbdmp.ws/api/v3/search/{domain}"
    data = http_get_json(url, timeout=HTTP_TIMEOUT)
    if not data:
        return []
    pastes = []
    for entry in data.get("data", [])[:10]:
        pastes.append({
            "id": entry.get("id", ""),
            "text_preview": (entry.get("text", "")[:100] + "..."),
            "tags": entry.get("tags", []),
        })
    return pastes


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, progress_cb=None) -> dict:
    """
    Run all breach/leaked credential lookups.
    Returns: {
        "domain": str,
        "hibp_breaches": [...],
        "hibp_accounts": [...],
        "intelx": [...],
        "leaklookup": [...],
        "pastes": [...],
        "total_breaches": int,
        "has_hits": bool,
    }
    """
    domain = target.replace("www.", "").strip()

    results = {
        "domain": domain,
        "hibp_breaches": [],
        "hibp_accounts": [],
        "intelx": [],
        "leaklookup": [],
        "pastes": [],
    }

    if progress_cb:
        progress_cb("breach [HIBP]")
    results["hibp_breaches"] = _hibp_breaches(domain)
    rate_limit(0.5)

    if HIBP_API_KEY:
        if progress_cb:
            progress_cb("breach [HIBP accounts]")
        results["hibp_accounts"] = _hibp_domain(domain)
        rate_limit(0.5)

    if INTELX_API_KEY:
        if progress_cb:
            progress_cb("breach [IntelX]")
        results["intelx"] = _intelx(domain)
        rate_limit(0.5)

    if progress_cb:
        progress_cb("breach [LeakLookup]")
    results["leaklookup"] = _leaklookup(domain)
    rate_limit(0.5)

    if progress_cb:
        progress_cb("breach [Pastes]")
    results["pastes"] = _psbdmp(domain)

    total = (
        len(results["hibp_breaches"])
        + len(results["intelx"])
        + len(results["leaklookup"])
    )
    results["total_breaches"] = total
    results["has_hits"] = total > 0 or len(results["pastes"]) > 0

    return results
