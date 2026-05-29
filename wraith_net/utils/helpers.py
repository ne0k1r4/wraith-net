"""
wraith_net/utils/helpers.py — Shared HTTP session, DNS, IP utilities
"""

import socket
import urllib.request
import urllib.error
import urllib.parse
import json
import ssl
import time
from typing import Optional


# ── HTTP ──────────────────────────────────────────────────────────────────────

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "application/json, text/html, */*",
}


def http_get(url: str, headers: dict = None, timeout: int = 10) -> Optional[bytes]:
    h = {**HEADERS, **(headers or {})}
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return resp.read()
    except Exception:
        return None


def http_get_json(url: str, headers: dict = None, timeout: int = 10) -> Optional[dict]:
    # TODO: need a cleaner way to handle connection retries for crt.sh
    # currently it just returns None when it throws 502/504
    data = http_get(url, headers=headers, timeout=timeout)
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


def http_get_response(url: str, headers: dict = None, timeout: int = 10):
    """Returns (status, headers_dict, body_str) or None on failure."""
    h = {**HEADERS, **(headers or {})}
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
        except Exception:
            return e.code, {}, ""
    except Exception:
        return None


# ── DNS ───────────────────────────────────────────────────────────────────────

def resolve_domain(domain: str) -> list[str]:
    try:
        info = socket.getaddrinfo(domain, None)
        return list({r[4][0] for r in info})
    except Exception:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── Port probe ────────────────────────────────────────────────────────────────

def tcp_probe(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                return None
    except Exception:
        return None


# ── Misc ──────────────────────────────────────────────────────────────────────

def normalize_domain(target: str) -> str:
    """Strip scheme and trailing slashes."""
    t = target.strip()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t.rstrip("/").split("/")[0]


def rate_limit(delay: float = 0.3):
    time.sleep(delay)
