"""
wraith_net/cli.py — Command-line interface
"""

import argparse
import sys
from wraith_net.utils.banner import print_banner, console
from wraith_net.utils.helpers import normalize_domain
from wraith_net.core.config import S


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wraith-net",
        description="WRAITH-NET v1.0 — Attack Surface Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wraith-net scan example.com
  wraith-net scan example.com --modules subdomains ports techstack
  wraith-net scan example.com --output ~/ops/reports/
  wraith-net scan example.com --ports 22,80,443,8080
  wraith-net quick example.com
        """,
    )
    sub = p.add_subparsers(dest="command")

    # scan
    scan = sub.add_parser("scan", help="Full attack surface scan")
    scan.add_argument("target", help="Domain or IP to scan")
    scan.add_argument(
        "--modules", nargs="+",
        choices=["subdomains", "ports", "techstack", "breach", "shodan",
                 "intel", "dns_security", "takeover", "risk", "report"],
        default=None,
        help="Modules to run (default: all)",
    )
    scan.add_argument("--output", "-o", default=None, help="Output directory for reports")
    scan.add_argument(
        "--ports", default=None,
        help="Custom ports (comma-separated, e.g. 22,80,443)",
    )
    scan.add_argument(
        "--axfr", action="store_true", default=False,
        help="Attempt AXFR zone transfer against NS servers",
    )
    scan.add_argument(
        "--brute-subs", action="store_true", default=False,
        help="Brute force subdomains using built-in wordlist (120 entries)",
    )
    scan.add_argument(
        "--wordlist", default=None,
        help="Path to custom wordlist file for --brute-subs",
    )

    # quick — subdomains + ports + techstack only
    quick = sub.add_parser("quick", help="Quick scan (no breach/shodan)")
    quick.add_argument("target", help="Domain or IP")
    quick.add_argument("--output", "-o", default=None, help="Output directory")

    # report — just generate report from existing JSON
    report = sub.add_parser("report", help="Generate report from existing JSON result")
    report.add_argument("json_file", help="Path to WRAITH-NET JSON result file")
    report.add_argument("--output", "-o", default=None)

    # version
    sub.add_parser("version", help="Show version")

    return p


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        from wraith_net import __version__, __author__
        console.print(f"[{S['title']}]WRAITH-NET[/{S['title']}] [{S['data']}]v{__version__}[/{S['data']}] — {__author__}")
        return

    if args.command in ("scan", "quick"):
        from wraith_net.core.engine import run

        target = normalize_domain(args.target)
        console.print(f"[{S['dim']}]Target[/{S['dim']}] : [{S['title']}]{target}[/{S['title']}]\n")

        if args.command == "quick":
            modules = ["subdomains", "ports", "techstack", "report"]
        else:
            modules = args.modules  # None = all

        custom_ports = None
        if hasattr(args, "ports") and args.ports:
            try:
                custom_ports = [int(p) for p in args.ports.split(",")]
            except ValueError:
                console.print(f"[{S['err']}]Invalid ports format. Use: 22,80,443[/{S['err']}]")
                sys.exit(1)

        try:
            run._axfr  = getattr(args, "axfr", False)
            run._brute = getattr(args, "brute_subs", False)
            if getattr(args, "wordlist", None):
                try:
                    run._wordlist = open(args.wordlist).read().splitlines()
                except Exception:
                    run._wordlist = None
            run(target, modules=modules, output_dir=getattr(args, "output", None))
        except KeyboardInterrupt:
            console.print(f"\n[{S['warn']}]Interrupted.[/{S['warn']}]")
            sys.exit(130)

    elif args.command == "report":
        import json
        from pathlib import Path
        from wraith_net.modules.reporter import run as gen_report

        json_path = Path(args.json_file)
        if not json_path.exists():
            console.print(f"[{S['err']}]File not found: {json_path}[/{S['err']}]")
            sys.exit(1)

        with open(json_path) as f:
            data = json.load(f)

        target = data.get("meta", {}).get("target", "unknown")
        results = data.get("results", data)
        rpt = gen_report(target, results, output_dir=args.output)

        console.print(f"[{S['ok']}]Report generated:[/{S['ok']}]")
        console.print(f"  MD   : {rpt['markdown']}")
        console.print(f"  JSON : {rpt['json']}")
        console.print(f"  HTML : {rpt['html']}")


if __name__ == "__main__":
    main()
