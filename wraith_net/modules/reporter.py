"""
wraith_net/modules/reporter.py — Strike report generator
Outputs: Markdown, JSON, HTML (Death Note themed)
"""

import json
import datetime
from pathlib import Path
from wraith_net.core.config import REPORTS_DIR


# ── Risk scorer ───────────────────────────────────────────────────────────────

def calculate_risk(results: dict) -> tuple[float, list[str]]:
    score = 0.0
    findings = []

    # Subdomains — large count is informational, not inherently risky
    sub_count = results.get("subdomains", {}).get("count", 0)
    if sub_count > 100:
        score += 5
        findings.append(f"⚠ Large attack surface: {sub_count} subdomains discovered")
    elif sub_count > 30:
        score += 2
        findings.append(f"⚠ Large attack surface: {sub_count} subdomains discovered")

    # Open ports — only truly dangerous ones score high
    ports = results.get("ports", {}).get("open_ports", [])
    HIGH_RISK_PORTS  = {23, 3389, 5900, 445}   # telnet, rdp, vnc, smb
    MED_RISK_PORTS   = {22, 3306, 27017, 9200, 6379, 5432, 1433}  # ssh, dbs
    for p in ports:
        port_num = p.get("port", 0)
        if port_num in HIGH_RISK_PORTS:
            score += 10
            findings.append(f"🔴 High-risk port exposed: {port_num}/{p.get('service','?')}")
        elif port_num in MED_RISK_PORTS:
            score += 3
            findings.append(f"⚠ Sensitive port exposed: {port_num}/{p.get('service','?')}")

    # Breach data — high impact
    breach = results.get("breach", {})
    b_count = breach.get("total_breaches", 0)
    score += b_count * 10
    if b_count > 0:
        findings.append(f"🔴 {b_count} breach source(s) found — credentials may be leaked")
    if breach.get("pastes"):
        score += len(breach["pastes"]) * 3
        findings.append(f"⚠ {len(breach['pastes'])} paste(s) referencing target")

    # Known CVEs — critical signal
    vuln_count = results.get("shodan", {}).get("vuln_count", 0)
    score += vuln_count * 12
    vulns = results.get("shodan", {}).get("known_vulns", [])
    for v in vulns:
        findings.append(f"🔴 Known CVE: {v}")

    # DNS security — moderate weight
    dns = results.get("dns_security", {})
    if dns:
        if not dns.get("spf", {}).get("present"):
            score += 5
            findings.append("⚠ No SPF record — domain spoofing possible")
        if not dns.get("dmarc", {}).get("present"):
            score += 5
            findings.append("⚠ No DMARC record — phishing undetected")
        elif dns.get("dmarc", {}).get("policy") == "none":
            score += 2
            findings.append("⚠ DMARC policy=none — monitoring only")
        if not dns.get("dkim", {}).get("present"):
            score += 3
            findings.append("⚠ No DKIM selector found")

    # Takeover — critical if confirmed
    takeover = results.get("takeover", {})
    if takeover.get("vuln_count", 0) > 0:
        score += takeover["vuln_count"] * 15
        for v in takeover.get("vulnerable", []):
            findings.append(f"🔴 Subdomain takeover: {v['fqdn']} → {v['service']}")
    elif takeover.get("possible_count", 0) > 0:
        score += 2
        findings.append(f"⚠ {takeover['possible_count']} possible takeover(s) — verify manually")

    # Tech stack
    tech = results.get("techstack", {})
    if tech.get("waf") is None:
        score += 3
        findings.append("⚠ No WAF detected — unprotected origin")
    else:
        findings.append(f"ℹ WAF detected: {tech.get('waf')}")

    cms = tech.get("cms")
    if cms:
        score += 2
        findings.append(f"ℹ CMS: {cms} — check for known vulns")

    ssl_data = tech.get("ssl", {})
    if not ssl_data:
        score += 4
        findings.append("⚠ SSL certificate absent or inaccessible")

    return round(score, 1), findings


def _risk_label(score: float) -> str:
    if score >= 40:
        return "CRITICAL"
    elif score >= 25:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    elif score >= 3:
        return "LOW"
    else:
        return "CLEAN"
    return "LOW"


# ── Markdown ──────────────────────────────────────────────────────────────────

def _generate_markdown(target: str, results: dict, score: float, findings: list) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label = _risk_label(score)
    lines = [
        f"# WRAITH-NET — Strike Report",
        f"",
        f"| Field    | Value |",
        f"|----------|-------|",
        f"| Target   | `{target}` |",
        f"| Date     | {now} |",
        f"| Risk     | **{label}** ({score}) |",
        f"| Author   | Light (Neok1ra) |",
        f"",
        f"---",
        f"",
        f"## Key Findings",
        "",
    ]
    for f in findings:
        lines.append(f"- {f}")

    # Subdomains
    subs = results.get("subdomains", {}).get("subdomains", [])
    lines += [
        "", f"---", "",
        f"## Subdomain Enumeration ({len(subs)} found)",
        "",
        "```",
    ]
    lines += subs[:50]
    if len(subs) > 50:
        lines.append(f"... and {len(subs) - 50} more")
    lines.append("```")

    # Open ports
    ports = results.get("ports", {}).get("open_ports", [])
    lines += [
        "", f"---", "",
        f"## Port Scan ({len(ports)} open ports)",
        "",
        "| Port | Service | Sensitive | Banner |",
        "|------|---------|-----------|--------|",
    ]
    for p in ports:
        banner = (p.get("banner", "") or "")[:60].replace("|", "\\|")
        lines.append(
            f"| {p['port']} | {p['service']} | {'⚠' if p.get('sensitive') else ''} | {banner} |"
        )

    # Tech stack
    tech = results.get("techstack", {})
    lines += [
        "", f"---", "",
        f"## Technology Stack",
        "",
        f"- **Server**: {tech.get('server', 'N/A')}",
        f"- **WAF**: {tech.get('waf') or 'Not detected'}",
        f"- **CMS**: {tech.get('cms') or 'N/A'}",
        f"- **Technologies**: {', '.join(tech.get('technologies', [])) or 'N/A'}",
        f"- **Versions**: {json.dumps(tech.get('versions', {}))}",
    ]

    # Breach
    breach = results.get("breach", {})
    lines += [
        "", f"---", "",
        f"## Breach Intelligence",
        "",
        f"- Total breach sources: **{breach.get('total_breaches', 0)}**",
        f"- Paste hits: **{len(breach.get('pastes', []))}**",
    ]
    for b in breach.get("hibp_breaches", []):
        lines.append(
            f"  - `{b.get('name')}` ({b.get('date')}) — {b.get('pwn_count', 0):,} accounts — {', '.join(b.get('data_classes', []))}"
        )

    # Shodan
    shodan = results.get("shodan", {})
    vulns = shodan.get("known_vulns", [])
    lines += [
        "", f"---", "",
        f"## Shodan / Censys Intel",
        "",
        f"- IP: `{shodan.get('ip', 'N/A')}`",
        f"- Org: {shodan.get('shodan_free', {}).get('org', shodan.get('shodan', {}).get('org', 'N/A'))}",
        f"- Known CVEs: {', '.join(vulns) if vulns else 'None'}",
    ]

    lines += [
        "", "---",
        "",
        "_Generated by WRAITH-NET v1.0 — Developed by Light (Neok1ra)_",
    ]
    return "\n".join(lines)


# ── JSON ──────────────────────────────────────────────────────────────────────

def _generate_json(target: str, results: dict, score: float, findings: list) -> str:
    output = {
        "meta": {
            "tool": "WRAITH-NET",
            "version": "1.0.0",
            "author": "Light (Neok1ra)",
            "target": target,
            "date": datetime.datetime.now().isoformat(),
            "risk_score": score,
            "risk_label": _risk_label(score),
        },
        "findings": findings,
        "results": results,
    }
    return json.dumps(output, indent=2, default=str)


# ── HTML ──────────────────────────────────────────────────────────────────────

def _generate_html(target: str, results: dict, score: float, findings: list) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label = _risk_label(score)
    risk_colors = {
        "CRITICAL": "#cc0000",
        "HIGH":     "#cc6600",
        "MEDIUM":   "#ccaa00",
        "LOW":      "#00cc44",
    }
    rcolor = risk_colors.get(label, "#e8d5c4")

    subs = results.get("subdomains", {}).get("subdomains", [])
    ports = results.get("ports", {}).get("open_ports", [])
    tech  = results.get("techstack", {})
    breach = results.get("breach", {})
    shodan = results.get("shodan", {})

    sub_rows = "".join(f"<tr><td>{s}</td></tr>" for s in subs[:50])
    port_rows = "".join(
        f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
        f"<td style='color:{'#cc0000' if p.get('sensitive') else '#00cc44'}'>{'⚠ SENSITIVE' if p.get('sensitive') else 'OK'}</td>"
        f"<td>{(p.get('banner','') or '')[:60]}</td></tr>"
        for p in ports
    )
    finding_rows = "".join(f"<li>{f}</li>" for f in findings)
    breach_rows = "".join(
        f"<tr><td>{b.get('name')}</td><td>{b.get('date')}</td>"
        f"<td>{b.get('pwn_count',0):,}</td><td>{', '.join(b.get('data_classes',[]))}</td></tr>"
        for b in breach.get("hibp_breaches", [])
    )
    vuln_list = "".join(f"<span class='tag red'>{v}</span>" for v in shodan.get("known_vulns", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WRAITH-NET — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0000; color: #e8d5c4; font-family: 'Courier New', monospace; padding: 2rem; }}
  h1   {{ color: #cc0000; font-size: 2rem; letter-spacing: 4px; margin-bottom: 0.3rem; }}
  h2   {{ color: #cc0000; font-size: 1.1rem; margin: 2rem 0 0.8rem; border-left: 3px solid #cc0000; padding-left: 0.8rem; }}
  .sub {{ color: #7a5a4a; font-size: 0.85rem; margin-bottom: 2rem; }}
  .meta-row {{ display: flex; gap: 2rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .meta-card {{ background: #120000; border: 1px solid #2a0000; padding: 1rem 1.5rem; border-radius: 4px; min-width: 160px; }}
  .meta-card label {{ color: #7a5a4a; font-size: 0.75rem; text-transform: uppercase; display: block; margin-bottom: 0.3rem; }}
  .meta-card span {{ font-size: 1.1rem; font-weight: bold; }}
  .risk {{ color: {rcolor}; }}
  .findings {{ list-style: none; padding: 0; }}
  .findings li {{ padding: 0.4rem 0; border-bottom: 1px solid #1a0000; font-size: 0.9rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th, td {{ text-align: left; padding: 0.5rem 0.8rem; border-bottom: 1px solid #1a0000; font-size: 0.85rem; }}
  th {{ color: #cc0000; background: #0f0000; }}
  tr:hover {{ background: #120000; }}
  .tag {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 3px; font-size: 0.75rem; margin: 0.15rem; }}
  .tag.red {{ background: #2a0000; color: #cc0000; border: 1px solid #cc0000; }}
  .tag.gray {{ background: #1a0000; color: #7a5a4a; }}
  footer {{ margin-top: 3rem; color: #3a2a1a; font-size: 0.75rem; text-align: center; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem; }}
  .kv {{ display: flex; gap: 0.5rem; padding: 0.35rem 0; border-bottom: 1px solid #1a0000; font-size: 0.85rem; }}
  .kv label {{ color: #7a5a4a; min-width: 110px; }}
</style>
</head>
<body>

<h1>WRAITH-NET</h1>
<div class="sub">Attack Surface Intelligence Report &nbsp;|&nbsp; {now}</div>

<div class="meta-row">
  <div class="meta-card"><label>Target</label><span>{target}</span></div>
  <div class="meta-card"><label>Risk Score</label><span class="risk">{score} — {label}</span></div>
  <div class="meta-card"><label>Subdomains</label><span>{len(subs)}</span></div>
  <div class="meta-card"><label>Open Ports</label><span>{len(ports)}</span></div>
  <div class="meta-card"><label>Breach Sources</label><span>{breach.get('total_breaches',0)}</span></div>
  <div class="meta-card"><label>Known CVEs</label><span class="risk">{shodan.get('vuln_count',0)}</span></div>
</div>

<h2>Key Findings</h2>
<ul class="findings">{finding_rows}</ul>

<h2>Subdomain Enumeration ({len(subs)} found)</h2>
<table><thead><tr><th>Subdomain</th></tr></thead><tbody>{sub_rows}</tbody></table>
{'<p style="color:#7a5a4a;font-size:0.8rem;margin-top:0.5rem">Showing first 50 results.</p>' if len(subs) > 50 else ''}

<h2>Port Scan ({len(ports)} open)</h2>
<table><thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th></tr></thead><tbody>{port_rows}</tbody></table>

<h2>Technology Stack</h2>
<div class="grid">
  <div>
    <div class="kv"><label>Server</label><span>{tech.get('server','N/A')}</span></div>
    <div class="kv"><label>WAF</label><span>{tech.get('waf') or 'Not detected'}</span></div>
    <div class="kv"><label>CMS</label><span>{tech.get('cms') or 'N/A'}</span></div>
    <div class="kv"><label>Status Code</label><span>{tech.get('status_code','N/A')}</span></div>
  </div>
  <div>
    {"".join(f'<span class="tag gray">{t}</span>' for t in tech.get("technologies", []))}
  </div>
</div>

<h2>Known CVEs</h2>
<div>{vuln_list if vuln_list else '<span style="color:#7a5a4a">None detected via free sources.</span>'}</div>

<h2>Breach Intelligence</h2>
{'<table><thead><tr><th>Breach</th><th>Date</th><th>Accounts</th><th>Data Classes</th></tr></thead><tbody>' + breach_rows + '</tbody></table>' if breach_rows else '<p style="color:#7a5a4a">No breaches found via public sources.</p>'}

<footer>Generated by WRAITH-NET v1.0 — Developed by Light (Neok1ra)</footer>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────

def run(target: str, all_results: dict, output_dir: Path = None) -> dict:
    """
    Generate MD, JSON, HTML reports.
    Returns: {"markdown": path, "json": path, "html": path, "score": float, "findings": list}
    """
    score, findings = calculate_risk(all_results)
    out_dir = output_dir or REPORTS_DIR
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe = target.replace(".", "_").replace("/", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"wraith_{safe}_{ts}"

    md_path   = base.with_suffix(".md")
    json_path = base.with_suffix(".json")
    html_path = base.with_suffix(".html")

    md_path.write_text(_generate_markdown(target, all_results, score, findings))
    json_path.write_text(_generate_json(target, all_results, score, findings))
    html_path.write_text(_generate_html(target, all_results, score, findings))

    return {
        "markdown": str(md_path),
        "json": str(json_path),
        "html": str(html_path),
        "score": score,
        "findings": findings,
        "risk_label": _risk_label(score),
    }
