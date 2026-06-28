"""
wraith_net/core/config.py — Configuration & constants
"""

import os
from pathlib import Path

# Theme colors (Dracula Palette)
PALETTE = {
    "bg":     "#282a36",
    "purple": "#bd93f9",
    "pink":   "#ff79c6",
    "cyan":   "#8be9fd",
    "dim":    "#6272a4",
    "white":  "#f8f8f2",
    "green":  "#50fa7b",
    "yellow": "#f1fa8c",
}

# Rich style shortcuts
S = {
    "title":   "bold #bd93f9",  # Purple
    "info":    "#f8f8f2",       # FG
    "dim":     "#6272a4",       # Comment/Grey
    "ok":      "bold #50fa7b",  # Green
    "warn":    "bold #f1fa8c",  # Yellow
    "err":     "bold #ff5555",  # Red
    "head":    "bold #ff79c6",  # Pink
    "data":    "#f8f8f2",
}

# Path setup
HOME         = Path.home()
DATA_DIR     = HOME / ".wraith-net"
REPORTS_DIR  = DATA_DIR / "reports"
CACHE_DIR    = DATA_DIR / "cache"

for d in (DATA_DIR, REPORTS_DIR, CACHE_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Config file loader
import json
_cfg = {}
_cfg_file = DATA_DIR / "config.json"
if _cfg_file.exists():
    try:
        _cfg = json.loads(_cfg_file.read_text())
    except Exception:
        pass

# API credentials configuration
SHODAN_API_KEY   = _cfg.get("shodan_api_key") or os.environ.get("SHODAN_API_KEY")
CENSYS_API_ID    = _cfg.get("censys_api_id") or os.environ.get("CENSYS_API_ID")
CENSYS_API_SEC   = _cfg.get("censys_api_secret") or os.environ.get("CENSYS_API_SECRET")
HIBP_API_KEY     = _cfg.get("hibp_api_key") or os.environ.get("HIBP_API_KEY")
INTELX_API_KEY   = _cfg.get("intelx_api_key") or os.environ.get("INTELX_API_KEY")
OTX_API_KEY      = _cfg.get("otx_api_key") or os.environ.get("OTX_API_KEY")
VIRUSTOTAL_API_KEY = _cfg.get("virustotal_api_key") or os.environ.get("VIRUSTOTAL_API_KEY")
GITHUB_API_KEY   = _cfg.get("github_api_key") or os.environ.get("GITHUB_API_KEY")

# Connection timeouts
HTTP_TIMEOUT     = 10
PORT_TIMEOUT     = 1.5
MAX_THREADS      = 100

# Audited port definitions
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888, 9200, 27017
]

# Technology detection patterns
TECH_SIGNATURES = {
    # Headers
    "headers": {
        "X-Powered-By":    {"php": "PHP", "asp": "ASP.NET", "express": "Express.js"},
        "Server":          {
            "apache": "Apache", "nginx": "Nginx", "iis": "IIS",
            "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
        },
        "X-Generator":     {"wordpress": "WordPress", "drupal": "Drupal"},
        "X-Drupal-Cache":  {"": "Drupal"},
        "X-WP-Nonce":      {"": "WordPress"},
        "CF-Ray":          {"": "Cloudflare"},
        "X-Shopify-Stage": {"": "Shopify"},
    },
    # Body patterns (regex)
    "body": {
        r"wp-content|wp-includes":         "WordPress",
        r"Joomla":                          "Joomla",
        r"Drupal\.settings":                "Drupal",
        r"next\.js|__NEXT_DATA__":          "Next.js",
        r"<div id=\"app\">|vue\.js":        "Vue.js",
        r"ng-version|angular\.min\.js":     "Angular",
        r"react\.development|__reactFiber": "React",
        r"jquery\.min\.js|jquery\.js":      "jQuery",
        r"shopify\.com\/s\/":               "Shopify",
        r"cdn\.squarespace\.com":           "Squarespace",
        r"wix\.com\/":                      "Wix",
        r"ghost\.io|content\.ghost\.org":   "Ghost",
    },
}

# Heuristics weights configuration
RISK_WEIGHTS = {
    "open_port":          1,
    "sensitive_port":     5,   # 22, 23, 3389, 5900
    "subdomain":          0.5,
    "breach_hit":         10,
    "tech_cve_known":     8,
    "shodan_vuln":        12,
    "censys_exposure":    6,
}

SENSITIVE_PORTS = {22, 23, 3389, 5900, 445, 3306, 27017, 9200, 6379, 5432}
