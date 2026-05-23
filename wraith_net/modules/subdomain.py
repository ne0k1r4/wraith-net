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



# ── AXFR Zone Transfer ────────────────────────────────────────────────────────

def _axfr(domain: str) -> set[str]:
    """
    Attempt DNS zone transfer (AXFR) against all NS records.
    This is a legitimate recon technique — misconfigured DNS servers
    may allow zone transfers, leaking all DNS records.
    """
    import socket, struct

    def _get_ns(domain: str) -> list[str]:
        """Get NS records via Google DNS."""
        import urllib.request, json
        try:
            url = f"https://dns.google/resolve?name={domain}&type=NS"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NET/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            return [
                ans["data"].rstrip(".")
                for ans in data.get("Answer", [])
                if ans.get("type") == 2
            ]
        except Exception:
            return []

    def _build_axfr_query(domain: str) -> bytes:
        """Build a raw DNS AXFR query packet."""
        name_parts = domain.encode().split(b".")
        qname = b""
        for part in name_parts:
            qname += bytes([len(part)]) + part
        qname += b"\x00"
        # Transaction ID + flags + QDCOUNT=1 + ANCOUNT=0 + NSCOUNT=0 + ARCOUNT=0
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # QTYPE=252 (AXFR) QCLASS=1 (IN)
        question = qname + struct.pack(">HH", 252, 1)
        # TCP DNS requires 2-byte length prefix
        msg = header + question
        return struct.pack(">H", len(msg)) + msg

    def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
        """Parse DNS wire-format name, handle compression pointers."""
        labels = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:  # compression pointer
                if offset + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                name, _ = _parse_dns_name(data, ptr)
                labels.append(name)
                offset += 2
                break
            else:
                offset += 1
                try:
                    labels.append(data[offset:offset + length].decode("ascii", "ignore"))
                except Exception:
                    pass
                offset += length
        return ".".join(labels).rstrip("."), offset

    def _parse_names_from_axfr(data: bytes, domain: str) -> set[str]:
        """Parse all DNS names from raw AXFR TCP response."""
        found = set()
        pos   = 0
        domain_lower = domain.lower()

        while pos < len(data) - 2:
            try:
                msg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                if msg_len == 0 or pos + msg_len > len(data):
                    break
                msg = data[pos:pos + msg_len]
                pos += msg_len

                if len(msg) < 12:
                    continue

                ancount = struct.unpack(">H", msg[6:8])[0]
                arcount = struct.unpack(">H", msg[10:12])[0]

                # Skip question section
                qpos = 12
                try:
                    _, qpos = _parse_dns_name(msg, qpos)
                    qpos += 4  # QTYPE + QCLASS
                except Exception:
                    continue

                # Parse answer records
                for _ in range(ancount + arcount):
                    if qpos + 10 > len(msg):
                        break
                    try:
                        name, qpos = _parse_dns_name(msg, qpos)
                        if qpos + 10 > len(msg):
                            break
                        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[qpos:qpos + 10])
                        qpos += 10
                        # Collect valid subdomains
                        name_lower = name.lower().rstrip(".")
                        if (name_lower.endswith(f".{domain_lower}")
                                and name_lower != domain_lower
                                and len(name_lower) > 0):
                            found.add(name_lower)
                        # Also parse RDATA names (CNAME, NS, MX, etc.)
                        if rtype in (5, 2, 15) and qpos + rdlen <= len(msg):
                            rdata_name, _ = _parse_dns_name(msg, qpos)
                            rdata_lower = rdata_name.lower().rstrip(".")
                            if (rdata_lower.endswith(f".{domain_lower}")
                                    and rdata_lower != domain_lower):
                                found.add(rdata_lower)
                        qpos += rdlen
                    except Exception:
                        break
            except Exception:
                break

        return found

    found = set()
    ns_servers = _get_ns(domain)

    for ns in ns_servers:
        try:
            # Resolve NS to IP
            ns_ip = socket.gethostbyname(ns)
            # Connect TCP port 53
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((ns_ip, 53))
            s.sendall(_build_axfr_query(domain))
            # Receive response (up to 64KB)
            data = b""
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()

            if len(data) > 100:
                names = _parse_names_from_axfr(data, domain)
                found |= names
        except Exception:
            continue

    return found


# ── Subdomain Brute Force ─────────────────────────────────────────────────────

# Built-in wordlist — common subdomains
BUILTIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "host", "support", "dev", "web", "bbs", "ww2", "cpanel", "whm", "autodiscover",
    "autoconfig", "mx", "imap", "pop", "pop3", "exchange", "owa", "admin",
    "api", "app", "staging", "beta", "demo", "cdn", "static", "assets", "media",
    "images", "img", "download", "downloads", "backup", "old", "new", "help",
    "docs", "wiki", "git", "gitlab", "jenkins", "jira", "confluence", "monitor",
    "status", "dashboard", "panel", "internal", "intranet", "corp", "office",
    "login", "auth", "sso", "id", "accounts", "account", "profile", "user",
    "users", "customer", "clients", "client", "partner", "partners", "store",
    "ecommerce", "pay", "payment", "billing", "invoice", "cart", "checkout",
    "mobile", "android", "ios", "wap", "pda", "chat", "forum", "forums",
    "community", "social", "connect", "hub", "gateway", "proxy", "cache",
    "lb", "load", "cluster", "node", "worker", "jobs", "scheduler", "queue",
    "metrics", "grafana", "prometheus", "kibana", "elastic", "log", "logs",
    "sentry", "error", "report", "reports", "analytics", "tracking", "events",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "storage", "s3", "bucket", "data", "archive", "vault", "secret", "key",
    "smtp", "relay", "bounce", "campaign", "newsletter", "news", "rss",
    "search", "query", "api2", "v1", "v2", "graphql", "rest", "soap",
]


def _brute_subdomains(domain: str, wordlist: list[str] = None,
                      concurrency: int = 50, progress_cb=None) -> set[str]:
    """
    Brute force subdomains by resolving each candidate.
    Uses threading for speed. Default wordlist has 120 entries.
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    words = wordlist or BUILTIN_WORDLIST
    found = set()
    total = len(words)
    done = [0]

    def _resolve(sub: str) -> str | None:
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(_resolve, w): w for w in words}
        for fut in as_completed(futures):
            done[0] += 1
            result = fut.result()
            if result:
                found.add(result)
            if progress_cb and done[0] % 20 == 0:
                progress_cb(f"subdomain brute [{done[0]}/{total}]")

    return found


def run(target: str, progress_cb=None, brute: bool = False,
        axfr: bool = False, wordlist: list[str] = None) -> dict:
    """
    Run subdomain enumeration — passive sources + optional AXFR + optional brute.
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

    # AXFR zone transfer attempt
    axfr_results = []
    if axfr:
        if progress_cb:
            progress_cb("subdomain [AXFR zone transfer]")
        try:
            axfr_subs = _axfr(domain)
            source_counts["AXFR"] = len(axfr_subs)
            if axfr_subs:
                axfr_results = sorted(axfr_subs)
                all_subs |= axfr_subs
            else:
                source_counts["AXFR"] = 0
        except Exception:
            source_counts["AXFR"] = 0

    # Subdomain brute force
    brute_results = []
    if brute:
        if progress_cb:
            progress_cb("subdomain [brute force]")
        try:
            brute_subs = _brute_subdomains(domain, wordlist=wordlist,
                                            progress_cb=progress_cb)
            # Only count new ones not already found passively
            new_brute = brute_subs - all_subs
            source_counts["brute"] = len(new_brute)
            brute_results = sorted(new_brute)
            all_subs |= brute_subs
        except Exception:
            source_counts["brute"] = 0

    return {
        "subdomains": sorted(all_subs),
        "count": len(all_subs),
        "sources": source_counts,
        "domain": domain,
        "axfr_found": axfr_results,
        "axfr_vulnerable": len(axfr_results) > 0,
        "brute_found": brute_results,
    }
