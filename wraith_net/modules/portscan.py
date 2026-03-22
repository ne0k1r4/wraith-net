"""
wraith_net/modules/portscan.py — Async port/service discovery
Integrates with LightScan v2.0 PHANTOM if available, else built-in scanner.
"""

import asyncio
import socket
import concurrent.futures
from typing import Optional
from wraith_net.core.config import TOP_PORTS, SENSITIVE_PORTS, PORT_TIMEOUT, MAX_THREADS
from wraith_net.utils.helpers import resolve_domain, grab_banner


# ── Service name map ──────────────────────────────────────────────────────────
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
}


# ── LightScan integration ─────────────────────────────────────────────────────

def _try_lightscan(target: str, ports: list[int]) -> Optional[dict]:
    """Attempt to invoke LightScan v2.0 PHANTOM if installed."""
    try:
        import importlib
        ls = importlib.import_module("lightscan")
        scanner = ls.Scanner(target=target, ports=ports, timeout=PORT_TIMEOUT)
        results = scanner.scan()
        return {"source": "LightScan v2.0", "results": results}
    except (ImportError, AttributeError, Exception):
        return None


# ── Built-in async scanner ────────────────────────────────────────────────────

def _tcp_check(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True, ""
    except Exception:
        return port, False, ""


def _scan_ports(host: str, ports: list[int]) -> list[dict]:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(_tcp_check, host, p, PORT_TIMEOUT): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, _ = future.result()
            if is_open:
                service = SERVICE_MAP.get(port, "unknown")
                sensitive = port in SENSITIVE_PORTS
                banner = grab_banner(host, port, timeout=2.0)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "sensitive": sensitive,
                    "banner": banner or "",
                })
    return sorted(open_ports, key=lambda x: x["port"])


def run(target: str, ports: list[int] = None, progress_cb=None) -> dict:
    """
    Scan target for open ports + service banners.
    Returns: {
        "host": str,
        "ips": list,
        "open_ports": [...],
        "sensitive_ports": [...],
        "source": str,
    }
    """
    if ports is None:
        ports = TOP_PORTS

    if progress_cb:
        progress_cb("portscan [resolving]")

    ips = resolve_domain(target)
    host = ips[0] if ips else target

    # Try LightScan first
    ls_result = _try_lightscan(host, ports)

    if ls_result:
        open_ports = ls_result.get("results", {}).get("open_ports", [])
        source = "LightScan v2.0 PHANTOM"
    else:
        if progress_cb:
            progress_cb(f"portscan [scanning {len(ports)} ports]")
        open_ports = _scan_ports(host, ports)
        source = "WRAITH-NET built-in"

    sensitive = [p for p in open_ports if p.get("sensitive") or p.get("port") in SENSITIVE_PORTS]

    return {
        "host": target,
        "ips": ips,
        "open_ports": open_ports,
        "sensitive_ports": sensitive,
        "source": source,
        "count": len(open_ports),
    }
