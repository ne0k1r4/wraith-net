"""
wraith_net/core/engine.py — Orchestration engine
Runs all modules in sequence, manages progress, collects results.
"""

from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box
from rich.console import Console
from wraith_net.utils.banner import console, section, ok, warn, err, info, results_table, summary_panel
from wraith_net.core.config import S
from wraith_net import __version__

console = Console()


def _make_spinner(label: str) -> Progress:
    return Progress(
        SpinnerColumn(style="bold #cc0000"),
        TextColumn(f"[#7a5a4a]{label}[/#7a5a4a]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def run(target: str, modules: list = None, output_dir: str = None) -> dict:
    """
    Full pipeline: subdomain → portscan → techstack → breach → shodan → report
    """
    from wraith_net.modules import subdomain, portscan, techstack, breach, shodan_feed, reporter
    from pathlib import Path

    all_modules = ["subdomains", "ports", "techstack", "breach", "shodan", "report"]
    if modules:
        active = [m for m in all_modules if m in modules]
    else:
        active = all_modules

    all_results = {}
    status_log = []

    def _cb(msg: str):
        status_log.append(msg)

    # ── Subdomains ────────────────────────────────────────────────────────────
    if "subdomains" in active:
        section("MODULE 1 — Subdomain Enumeration")
        with _make_spinner("Querying passive DNS sources...") as p:
            p.add_task("")
            result = subdomain.run(target, progress_cb=_cb)
        all_results["subdomains"] = result
        ok(f"{result['count']} subdomains found")
        for src, count in result["sources"].items():
            info(f"{src}: {count}")

    # ── Port scan ─────────────────────────────────────────────────────────────
    if "ports" in active:
        section("MODULE 2 — Port / Service Discovery")
        with _make_spinner("Scanning top ports...") as p:
            p.add_task("")
            result = portscan.run(target, progress_cb=_cb)
        all_results["ports"] = result
        ok(f"{result['count']} open port(s) — via {result['source']}")
        if result["open_ports"]:
            rows = [
                (str(p["port"]), p["service"],
                 "⚠" if p.get("sensitive") else "✔",
                 (p.get("banner","") or "")[:50])
                for p in result["open_ports"]
            ]
            t = results_table("Open Ports", ["Port", "Service", "Risk", "Banner"], rows)
            console.print(t)
        if result["sensitive_ports"]:
            warn(f"{len(result['sensitive_ports'])} sensitive port(s) exposed")

    # ── Tech stack ────────────────────────────────────────────────────────────
    if "techstack" in active:
        section("MODULE 3 — Technology Fingerprinting")
        with _make_spinner("Fingerprinting...") as p:
            p.add_task("")
            result = techstack.run(target, progress_cb=_cb)
        all_results["techstack"] = result
        ok(f"Server: {result.get('server','?')} | CMS: {result.get('cms') or 'N/A'}")
        if result.get("technologies"):
            info(f"Stack: {', '.join(result['technologies'])}")
        if result.get("waf"):
            ok(f"WAF detected: {result['waf']}")
        else:
            warn("No WAF detected")
        if result.get("versions"):
            info(f"Versions: {result['versions']}")
        if result.get("ssl"):
            ok("SSL certificate present")

    # ── Breach ────────────────────────────────────────────────────────────────
    if "breach" in active:
        section("MODULE 4 — Breach Intelligence")
        with _make_spinner("Querying breach databases...") as p:
            p.add_task("")
            result = breach.run(target, progress_cb=_cb)
        all_results["breach"] = result
        if result["has_hits"]:
            warn(f"{result['total_breaches']} breach source(s) found")
            for b in result.get("hibp_breaches", []):
                info(f"[{b.get('date')}] {b.get('name')} — {b.get('pwn_count',0):,} accts")
        else:
            ok("No breach data found via public sources")
        if result.get("pastes"):
            warn(f"{len(result['pastes'])} paste reference(s) found")

    # ── Shodan ────────────────────────────────────────────────────────────────
    if "shodan" in active:
        section("MODULE 5 — Shodan / Censys Intel")
        with _make_spinner("Fetching threat intelligence...") as p:
            p.add_task("")
            result = shodan_feed.run(target, progress_cb=_cb)
        all_results["shodan"] = result
        idb = result.get("shodan_free", {})
        if idb:
            ok(f"InternetDB: {len(idb.get('ports',[]))} port(s), {len(idb.get('vulns',[]))} CVE(s)")
            for v in idb.get("vulns", []):
                warn(f"CVE: {v}")
        if result.get("shodan") and not result["shodan"].get("error"):
            ok(f"Shodan: org={result['shodan'].get('org')}, ASN={result['shodan'].get('asn')}")

    # ── Report ────────────────────────────────────────────────────────────────
    if "report" in active:
        section("MODULE 6 — Strike Report")
        out_path = Path(output_dir) if output_dir else None
        rpt = reporter.run(target, all_results, output_dir=out_path)
        all_results["report"] = rpt

        summary_panel(target, rpt["score"], rpt)
        console.print()
        for f in rpt["findings"]:
            console.print(f"  [{S['data']}]{f}[/{S['data']}]")

        console.print()
        ok(f"Markdown : {rpt['markdown']}")
        ok(f"JSON     : {rpt['json']}")
        ok(f"HTML     : {rpt['html']}")

    return all_results
