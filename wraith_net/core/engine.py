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
    Full pipeline: subdomain → portscan → techstack → breach → shodan →
                   dns_security → takeover → risk_score → report
    """
    from wraith_net.modules import (subdomain, portscan, techstack, breach,
                                    shodan_feed, reporter, dns_security,
                                    takeover, risk_score)
    from pathlib import Path

    all_modules = ["subdomains", "ports", "techstack", "breach", "shodan",
                   "dns_security", "takeover", "risk", "report"]
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

    # ── DNS Security ──────────────────────────────────────────────────────────
    if "dns_security" in active:
        section("MODULE 6 — DNS & Email Security")
        with _make_spinner("Checking SPF / DMARC / DKIM / DNSSEC...") as p:
            p.add_task("")
            result = dns_security.run(target, progress_cb=_cb)
        all_results["dns_security"] = result

        spf   = result.get("spf", {})
        dmarc = result.get("dmarc", {})
        dkim  = result.get("dkim", {})
        dnssec = result.get("dnssec", {})

        if spf.get("present") and spf.get("score", 0) >= 2:
            ok(f"SPF: {spf.get('record','')[:60]}")
        else:
            warn(f"SPF: {'missing' if not spf.get('present') else 'misconfigured'}")

        if dmarc.get("present") and dmarc.get("score", 0) >= 2:
            ok(f"DMARC: policy={dmarc.get('policy')}")
        else:
            policy_str = "missing" if not dmarc.get("present") else f"policy={dmarc.get('policy')}"
            warn(f"DMARC: {policy_str}")

        if dkim.get("present"):
            ok(f"DKIM: {dkim.get('count')} selector(s) found")
        else:
            warn("DKIM: no selectors found")

        if dnssec.get("enabled"):
            ok("DNSSEC: enabled")
        else:
            warn("DNSSEC: not enabled")

        for issue in result.get("issues", [])[:5]:
            warn(issue)

    # ── Subdomain Takeover ────────────────────────────────────────────────────
    if "takeover" in active:
        section("MODULE 7 — Subdomain Takeover Detection")
        subs = all_results.get("subdomains", {}).get("subdomains", [])
        sub_fqdns = [s if isinstance(s, str) else s.get("subdomain", "") for s in subs if s]
        with _make_spinner(f"Checking {len(sub_fqdns) or 'common'} subdomains...") as p:
            p.add_task("")
            result = takeover.run(target, subdomains=sub_fqdns or None, progress_cb=_cb)
        all_results["takeover"] = result

        if result["vuln_count"]:
            for v in result["vulnerable"]:
                warn(f"VULNERABLE: {v['fqdn']} → {v['service']} ({v['cname']})")
        elif result["possible_count"]:
            for v in result["possible"][:3]:
                info(f"POSSIBLE: {v['fqdn']} → {v['service']}")
        else:
            ok(f"No takeover vulnerabilities found ({result['subdomains_checked']} checked)")

    # ── Risk Score ────────────────────────────────────────────────────────────
    if "risk" in active:
        section("MODULE 8 — Risk Assessment")
        result = risk_score.run(target, all_results)
        all_results["risk"] = result

        grade = result["grade"]
        level = result["level"]
        color = result["color"]
        console.print(f"\n  Risk Grade: [{color}]{grade}[/{color}]  "
                      f"[{color}]{level}[/{color}]  "
                      f"(score {result['raw_score']}/{result['max_score']})\n")
        for issue in result["issues"][:10]:
            warn(issue) if "CONFIRMED" in issue or "No " in issue else info(issue)

    # ── Report ────────────────────────────────────────────────────────────────
    if "report" in active:
        section("MODULE 9 — Strike Report")
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
