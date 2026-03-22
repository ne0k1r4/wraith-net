# WRAITH-NET

```
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗      ███╗   ██╗███████╗████████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║      ████╗  ██║██╔════╝╚══██╔══╝
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║█████╗██╔██╗ ██║█████╗     ██║
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║╚════╝██║╚██╗██║██╔══╝     ██║
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║      ██║ ╚████║███████╗   ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

> **Attack Surface Intelligence Framework**
> Developed by **Light (Neok1ra)**

---

## Overview

WRAITH-NET is a passive + active attack surface mapper. Give it a domain — it returns a full pre-engagement intelligence report: subdomains, exposed ports, tech stack, leaked credentials, and CVEs from Shodan.

Designed to bridge **GhostRecon** (passive OSINT) and **LightScan v2.0 PHANTOM** (active scanner) into a single unified pre-engagement pipeline.

---

## Modules

| # | Module | Description | Requires Key? |
|---|--------|-------------|---------------|
| 1 | `subdomains` | Passive subdomain enum (crt.sh, HackerTarget, AlienVault, RapidDNS, BufferOver, ThreatCrowd) | No |
| 2 | `ports` | Port/service discovery + banner grabbing (LightScan hook or built-in async) | No |
| 3 | `techstack` | HTTP header + body fingerprinting, WAF detect, SSL info, CMS detection | No |
| 4 | `breach` | HIBP breach lookup, IntelX leaks, LeakLookup, paste search | Optional |
| 5 | `shodan` | Shodan InternetDB (free) + Shodan API + Censys host intel | Optional |
| 6 | `report` | Strike report — Markdown, JSON, HTML (Death Note themed) | No |

---

## Installation

```bash
# Clone
git clone git@github.com:ne0k1r4/wraith-net.git
cd wraith-net

# Install (no virtualenv needed)
pip install -e . --break-system-packages
```

---

## Usage

### Full scan
```bash
wraith-net scan example.com
```

### Quick scan (no breach/shodan — fast)
```bash
wraith-net quick example.com
```

### Selective modules
```bash
wraith-net scan example.com --modules subdomains ports techstack report
```

### Custom ports
```bash
wraith-net scan example.com --ports 22,80,443,8080,3306
```

### Custom output directory
```bash
wraith-net scan example.com --output ~/ops/reports/
```

### Regenerate report from existing JSON
```bash
wraith-net report ~/.wraith-net/reports/wraith_example_com_20260322.json
```

---

## API Keys (Optional)

Set via environment variables. Without keys, the tool still works — it uses free sources.

```bash
# Add to ~/.zshrc
export SHODAN_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export HIBP_API_KEY="your_key"
export INTELX_API_KEY="your_key"
export OTX_API_KEY="your_key"
```

---

## GRIMOIRE Integration

WRAITH-NET ships with a native GRIMOIRE v2+ module.

### Auto-load into GRIMOIRE

```bash
# Option A — copy grimoire module file
cp wraith_net/grimoire_module.py ~/Downloads/grimoire-v2/wraith_net_module.py

# Option B — wire via GRIMOIRE's module loader (add to grimoire's modules list)
```

### Use inside GRIMOIRE interactive shell

```
grimoire > wraith scan example.com
grimoire > wraith quick example.com
```

---

## Output

Reports are saved to `~/.wraith-net/reports/` by default.

```
wraith_example_com_20260322_143012.md    ← Markdown strike report
wraith_example_com_20260322_143012.json  ← Machine-readable full results
wraith_example_com_20260322_143012.html  ← Death Note themed HTML report
```

---

## Risk Scoring

| Score | Label    |
|-------|----------|
| 50+   | CRITICAL |
| 30–49 | HIGH     |
| 15–29 | MEDIUM   |
| 0–14  | LOW      |

Scoring factors: sensitive ports, breach hits, known CVEs, subdomain count, WAF absence, CMS presence.

---

## LightScan Integration

If **LightScan v2.0 PHANTOM** is installed (`pip install -e ~/tools/network/lightscan`), WRAITH-NET will automatically delegate port scanning to it. Falls back to the built-in async scanner if not found.

---

## File Structure

```
wraith-net/
├── wraith_net/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                  ← Entry point
│   ├── grimoire_module.py      ← GRIMOIRE integration
│   ├── core/
│   │   ├── config.py           ← Palette, API keys, constants
│   │   └── engine.py           ← Orchestration pipeline
│   ├── modules/
│   │   ├── subdomain.py        ← Passive subdomain enum
│   │   ├── portscan.py         ← Port/service discovery
│   │   ├── techstack.py        ← Tech fingerprinting
│   │   ├── breach.py           ← Breach/leak lookup
│   │   ├── shodan_feed.py      ← Shodan + Censys intel
│   │   └── reporter.py         ← MD/JSON/HTML report gen
│   └── utils/
│       ├── banner.py           ← Rich display + ASCII art
│       └── helpers.py          ← HTTP, DNS, TCP utilities
└── setup.py
```

---

## Disclaimer

WRAITH-NET is built for **authorized security assessments** — bug bounty, red team engagements, and penetration testing within legal scope. Scanning targets without permission violates §202a StGB (Germany) and equivalent laws worldwide. Always operate within authorized scope.

---

*WRAITH-NET v1.0.0 — Developed by Light (Neok1ra)*
