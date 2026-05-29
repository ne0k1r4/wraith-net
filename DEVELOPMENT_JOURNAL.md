# Dev Journal: WRAITH-NET Build Logs

A raw chronological log of how this got put together, what broke, and the hacks/fixes applied.

---

### May 22, 2026: The "Zero-Dependency" Lie
Wanted to build an OSINT/recon engine that didn't require installing a massive Go toolchain (like `subfinder` or `naabu`). Python standard library seemed perfect. 

**What broke immediately:** 
* `crt.sh` is notoriously unstable. Half the time it returns a 502 Bad Gateway or just hangs. Using standard `urllib.request` without a timeout meant the script would block indefinitely.
* **Fix**: Added a custom `HTTPClient` wrapper in `helpers.py` with strict 5-second timeouts and a retry loop. If `crt.sh` dies, it logs a warning and falls back to HackerTarget or AlienVault instead of crashing the pipeline.

---

### May 24, 2026: Port Probing is Insanely Slow
Added a simple TCP socket port scanner. Probing 20-30 ports across multiple hosts took ages. Running it sequentially is a complete bottleneck.

**The Fix:**
* Tried using `asyncio`, but standard library async socket operations get messy quickly when dealing with DNS resolution timeouts.
* **Fallback**: Swapped it to use a simple thread-pool executor. Kept the timeout tight (`0.5s` per connection). It's not as fancy as a raw SYN scanner (like masscan), but it's pure Python and finishes a quick-scan in under 15 seconds now.

---

### May 26, 2026: Subdomain Takeover Gaps
Built the takeover module check using standard CNAME records.

**Issues encountered:**
* GitHub Pages, Heroku, and S3 check patterns were throwing false positives when domains redirected to custom 404 pages. A DNS query showing a CNAME isn't enough; we need to verify the HTTP response body.
* **Fix**: Implemented a two-stage verification. Stage 1 checks the CNAME. If it matches a known service (e.g., `*.github.io`), Stage 2 does a quick HTTP request to check for signature strings (like `"There isn't a GitHub Pages site here"`).

---

### May 28, 2026: Death Note styling without frameworks
Wrote the HTML reporter. I wanted a dark, retro terminal aesthetic (dark red `#cc0000` accents on black `#0a0000`).

**The Struggle:**
* Keeping the report as a single self-contained file (so you can just open it in any browser or share it over Discord/Slack) meant no external CSS frameworks, no Google Fonts (might load offline), and no external Javascript.
* **Fix**: Inlined a minimal, responsive CSS grid using monospace system fonts. It looks raw, fast, and completely custom.

---

### May 29, 2026: Testing & Cleanup
Ran scans against `example.com` to check performance.
* Added a `quick` command mode for when you just want subdomains and open ports without querying the slower threat intel / breach databases.
* Generated markdown outputs and HTML reports inside the repo workspace directory for easier parsing.
