"""
wraith_net/grimoire_module.py — GRIMOIRE v2+ module integration
Drop this in your GRIMOIRE modules/ directory as wraith_net_module.py
or wire it via grimoire's module loader.

Usage inside GRIMOIRE:
    from wraith_net.grimoire_module import GrimoireWraithNet
    module = GrimoireWraithNet()
    module.run("example.com")
"""

from wraith_net.core.engine import run as _engine_run
from wraith_net.utils.banner import console
from wraith_net.utils.helpers import normalize_domain
from wraith_net.core.config import S


MODULE_META = {
    "name":    "wraith-net",
    "version": "1.0.0",
    "author":  "Light (Neok1ra)",
    "desc":    "Attack Surface Intelligence — passive recon + port scan + breach + shodan",
    "cmd":     "wraith",
}


class GrimoireWraithNet:
    """GRIMOIRE-compatible module interface."""

    name = "wraith-net"
    description = "Attack surface intelligence framework"

    def banner(self):
        from wraith_net.utils.banner import print_banner
        print_banner()

    def help(self):
        console.print(f"""
[{S['title']}]wraith-net[/{S['title']}] — Attack Surface Intelligence

[{S['dim']}]Commands:[/{S['dim']}]
  [{S['data']}]scan <target>[/{S['data']}]             Full pipeline (all modules)
  [{S['data']}]quick <target>[/{S['data']}]            Fast scan (no breach/shodan)
  [{S['data']}]scan <target> --modules ...[/{S['data']}]  Selective modules

[{S['dim']}]Modules:[/{S['dim']}]  subdomains, ports, techstack, breach, shodan, report
        """)

    def run(self, target: str, modules: list = None, output_dir: str = None) -> dict:
        """
        Run WRAITH-NET scan from within GRIMOIRE.
        Returns full results dict.
        """
        domain = normalize_domain(target)
        console.print(f"\n[{S['dim']}][wraith-net] Scanning:[/{S['dim']}] [{S['title']}]{domain}[/{S['title']}]\n")
        return _engine_run(domain, modules=modules, output_dir=output_dir)

    def interactive(self):
        """GRIMOIRE-style interactive prompt loop."""
        console.print(f"[{S['title']}]WRAITH-NET Interactive Mode[/{S['title']}]")
        console.print(f"[{S['dim']}]Type 'help' for commands, 'exit' to quit.[/{S['dim']}]\n")

        while True:
            try:
                raw = console.input(f"[{S['title']}]wraith[/{S['title']}][{S['dim']}]>[/{S['dim']}] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not raw:
                continue
            if raw in ("exit", "quit", "q"):
                break
            if raw == "help":
                self.help()
                continue

            parts = raw.split()
            cmd = parts[0].lower()

            if cmd == "scan" and len(parts) >= 2:
                self.run(parts[1])
            elif cmd == "quick" and len(parts) >= 2:
                self.run(parts[1], modules=["subdomains", "ports", "techstack", "report"])
            else:
                console.print(f"[{S['warn']}]Unknown command. Type 'help'.[/{S['warn']}]")


# ── Standalone GRIMOIRE loader hook ──────────────────────────────────────────

def load():
    """Called by GRIMOIRE's module loader."""
    return GrimoireWraithNet()
