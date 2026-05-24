<div align="center">

```
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗      ███╗   ██╗███████╗████████╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║      ████╗  ██║██╔════╝╚══██╔══╝
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║█████╗██╔██╗ ██║█████╗     ██║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║╚════╝██║╚██╗██║██╔══╝     ██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║      ██║ ╚████║███████╗   ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

[![Version](https://img.shields.io/badge/version-1.0.0-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4/wraith-net)
[![Python](https://img.shields.io/badge/python-3.10+-cc0000?style=for-the-badge&logo=python&logoColor=white&labelColor=0a0000)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-cc0000?style=for-the-badge&labelColor=0a0000)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-cc0000?style=for-the-badge&labelColor=0a0000)](https://archlinux.org)
[![Author](https://img.shields.io/badge/author-ne0k1r4-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4)

**Attack Surface Intelligence Framework**  
10-module passive + active recon pipeline · ASN/BGP · DNS security · GitHub dorking · Risk scoring

</div>

---

## Overview

WRAITH-NET is a comprehensive attack surface intelligence framework that correlates data from multiple sources into a single scored risk report. It goes beyond simple subdomain enumeration — combining passive OSINT, active DNS probing, threat intelligence, email security auditing, and infrastructure correlation.

```bash
wraith-net scan target.com
wraith-net scan target.com --axfr --brute-subs
wraith-net scan target.com --modules intel dns_security takeover
```

---

## 10-Module Pipeline

| # | Module | Type | Description |
|---|--------|------|-------------|
| 1 | **Subdomains** | Passive + Active | 6 OSINT sources · AXFR zone transfer · brute force |
| 2 | **Ports** | Active | Async TCP scan · banner grabbing · LightScan integration |
| 3 | **Techstack** | Passive | Server · WAF · CMS · SSL · framework fingerprinting |
| 4 | **Breach** | Passive | HIBP · IntelX · LeakLookup credential exposure |
| 5 | **Shodan** | Passive | InternetDB · Shodan · Censys host intelligence |
| 6 | **Intel** | Passive | ASN/BGP · reverse IP · CT certs · IP reputation · GitHub dorking |
| 7 | **DNS Security** | Active | SPF · DMARC · DKIM · DNSSEC · MX STARTTLS |
| 8 | **Takeover** | Active | 30-service CNAME fingerprinting · dangling subdomain detection |
| 9 | **Risk Score** | Analysis | Calibrated A–F grade across all module findings |
| 10 | **Report** | Output | Markdown · JSON · HTML dashboard with charts |

---

## Install

```bash
git clone https://github.com/ne0k1r4/wraith-net
cd wraith-net
pip install -e .
```

Zero hard dependencies — pure Python stdlib core.

---

## Usage

```bash
# Full scan (all 10 modules)
wraith-net scan target.com

# Full scan with active DNS
wraith-net scan target.com --axfr --brute-subs

# Specific modules only
wraith-net scan target.com --modules subdomains ports techstack

# Custom output directory
wraith-net scan target.com -o /tmp/reports

# Quick scan (subdomains + ports + techstack)
wraith-net quick target.com

# Re-render report from saved JSON
wraith-net report /path/to/result.json
```

---

## Module Details

<details>
<summary><b>Module 1 — Subdomain Enumeration</b></summary>
<br>

**Passive sources (6):**
- crt.sh — Certificate Transparency logs
- HackerTarget — passive DNS database
- AlienVault OTX — threat intelligence
- RapidDNS — passive DNS
- BufferOver — DNS over HTTP
- ThreatCrowd — threat intelligence graph

**Active sources (2):**
- AXFR zone transfer — attempts TCP DNS zone transfer against all NS servers
- Brute force — 155-entry built-in wordlist, custom wordlist support, concurrent resolution

```bash
wraith-net scan target.com --axfr --brute-subs
wraith-net scan target.com --brute-subs --wordlist /path/to/wordlist.txt
```

</details>

<details>
<summary><b>Module 6 — Threat Intelligence Correlation</b></summary>
<br>

- **ASN/BGP** — autonomous system, organization, country, city, IP prefix via ipinfo.io
- **BGP peers** — ASN name, description, RIR, abuse contact via bgpview.io
- **ASN prefixes** — all IP ranges announced by the target's ASN
- **Reverse IP** — co-hosted domains on same IP via HackerTarget
- **Certificate Transparency** — historical SSL certs from crt.sh
- **IP reputation** — offline blocklist (TOR exits, known malicious ranges, C2 ranges)
- **TOR exit check** — live DNS lookup against torproject.org DNSEL
- **GitHub dorking** — searches public repos for exposed credentials/tokens referencing target domain
- **VirusTotal** — domain reputation (optional API key)

</details>

<details>
<summary><b>Module 7 — DNS & Email Security</b></summary>
<br>

| Check | What it detects |
|-------|----------------|
| SPF | Missing, `+all` (open), `~all` (softfail), too many lookups, deprecated `ptr` |
| DMARC | Missing, `p=none` (no enforcement), missing `rua=`, subdomain policy gaps |
| DKIM | Probes 18 common selectors, flags weak key length and SHA-1 usage |
| DNSSEC | Checks DNSKEY records and AD bit via Google DNS |
| MX | STARTTLS banner grab on port 25, unusual TLD detection |

Risk score contribution: up to +6 for completely missing email security.

</details>

<details>
<summary><b>Module 8 — Subdomain Takeover</b></summary>
<br>

30 service fingerprints checked via CNAME matching + body verification:

GitHub Pages · Heroku · Netlify · AWS S3 · AWS CloudFront · Azure · Fastly · Ghost · Tumblr · Shopify · Webflow · Surge.sh · Zendesk · Freshdesk · HubSpot · Intercom · Unbounce · Readme.io · Bitbucket · Squarespace · Strikingly · Fly.io · Render · Vercel · Firebase · WP Engine · Pantheon · Cargo · Kinsta · Acquia

**Confirmed** = CNAME matches service + body fingerprint verified  
**Possible** = CNAME matches service, body fingerprint inconclusive

</details>

<details>
<summary><b>Module 9 — Risk Scoring</b></summary>
<br>

Calibrated scoring engine across all modules:

| Grade | Level | Score | Triggers |
|-------|-------|-------|---------|
| A | CLEAN | 0–2 | No significant findings |
| B | LOW | 3–9 | Minor misconfigs, SSH exposed |
| C | MEDIUM | 10–24 | Missing email security, no WAF |
| D | HIGH | 25–39 | Breach data, known CVEs, open RDP |
| F | CRITICAL | 40+ | Confirmed takeover, active exploitation, credential leak |

High-weight signals: confirmed subdomain takeover (+15/each), known CVE (+12/each), breach data (+10/source), RDP/VNC/Telnet exposed (+10), TOR exit node (+5).

Low-weight signals: SSH exposed (+3), large subdomain count (+5), no WAF (+3), missing DMARC (+5).

</details>

---

## Configuration

Optional API keys stored in `~/.wraith-net/config.json`:

```json
{
  "virustotal_api_key": "your_key",
  "github_api_key":     "your_pat",
  "shodan_api_key":     "your_key"
}
```

- **VirusTotal** — free at virustotal.com, 4 req/min
- **GitHub PAT** — free, increases dorking rate limit from 10 to 5000 req/hr
- **Shodan** — free at account.shodan.io

All modules work without API keys via free fallbacks.

---

## Output

Every scan generates 3 report formats in `~/.wraith-net/reports/`:

```
wraith_target_com_20260522_120000.md    # markdown findings table
wraith_target_com_20260522_120000.json  # full machine-readable data
wraith_target_com_20260522_120000.html  # dark themed interactive dashboard
```

Re-render any saved scan:

```bash
wraith-net report ~/.wraith-net/reports/wraith_target_com_20260522_120000.json
```

---

## Architecture

```
wraith_net/
├── cli.py                  argument parser · subcommands
├── core/
│   ├── engine.py           10-module pipeline orchestrator
│   └── config.py           constants · timeouts
├── modules/
│   ├── subdomain.py        6 passive sources + AXFR + brute force
│   ├── portscan.py         async TCP scanner
│   ├── techstack.py        HTTP fingerprinting · WAF · SSL
│   ├── breach.py           HIBP · IntelX · LeakLookup
│   ├── shodan_feed.py      Shodan · Censys · InternetDB
│   ├── intel.py            ASN/BGP · reverse IP · CT · GitHub dorks
│   ├── dns_security.py     SPF · DMARC · DKIM · DNSSEC · MX
│   ├── takeover.py         30-service CNAME fingerprinting
│   ├── risk_score.py       A–F calibrated scoring engine
│   └── reporter.py         MD · JSON · HTML report generation
└── utils/
    └── helpers.py          HTTP · DNS · socket helpers
```

---

## Disclaimer

For authorized security testing, bug bounty, and educational purposes only.  
Always obtain written permission before scanning systems you do not own.

---

<div align="center">
<br>
<i>WRAITH-NET v1.0.0 · Developer: Light (Neok1ra)</i>
<br><br>

[![GitHub](https://img.shields.io/badge/github.com%2Fne0k1r4-cc0000?style=flat-square&labelColor=0a0000&logo=github&logoColor=white)](https://github.com/ne0k1r4)

</div>
