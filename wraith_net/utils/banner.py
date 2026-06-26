"""
wraith_net/utils/banner.py — ASCII banner + Rich display helpers
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from wraith_net.core.config import S
import datetime

import time
from rich.columns import Columns
import sys
import os

console = Console()

BANNER = r"""
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗      ███╗   ██╗███████╗████████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║      ████╗  ██║██╔════╝╚══██╔══╝
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║█████╗██╔██╗ ██║█████╗     ██║   
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║╚════╝██║╚██╗██║██╔══╝     ██║   
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║      ██║ ╚████║███████╗   ██║   
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝  ╚═══╝╚══════╝   ╚═╝   
"""

TAGLINE = "[ Attack Surface Intelligence Framework ]"
AUTHOR  = "by Light (Neok1ra) — v1.0.0"


def print_banner():
    # If not running in a real interactive terminal session, print static banner to avoid messy logs
    if not sys.stdout.isatty() or os.environ.get("TERM") == "dumb":
        console.print(BANNER, style="bold #cc0000")
        console.print(f"  {TAGLINE}", style="#7a5a4a")
        console.print(f"  {AUTHOR}\n", style="#e8d5c4")
        return

    # Otherwise, play cool startup animations
    banner_lines = BANNER.strip("\n").split("\n")
    for line in banner_lines:
        console.print(line, style="bold #cc0000")
        time.sleep(0.03)
    
    tagline_text = f"  {TAGLINE}"
    for char in tagline_text:
        console.print(char, style="#7a5a4a", end="")
        time.sleep(0.008)
    console.print()
    
    author_text = f"  {AUTHOR}\n"
    for char in author_text:
        console.print(char, style="#e8d5c4", end="")
        time.sleep(0.006)


def section(title: str):
    console.print(f"\n[bold #cc0000]┌─[ [bold #ffffff]{title}[/bold #ffffff] ][/bold #cc0000]")


def ok(msg: str):
    console.print(f"[bold #00cc44]  ✔[/bold #00cc44] [{S['data']}]{msg}[/{S['data']}]")


def warn(msg: str):
    console.print(f"[bold #ccaa00]  ⚠[/bold #ccaa00] [{S['data']}]{msg}[/{S['data']}]")


def err(msg: str):
    console.print(f"[bold #cc0000]  ✘[/bold #cc0000] [{S['data']}]{msg}[/{S['data']}]")


def info(msg: str):
    console.print(f"[#7a5a4a]  ›[/#7a5a4a] [{S['data']}]{msg}[/{S['data']}]")


def get_spinner(label: str) -> Progress:
    return Progress(
        SpinnerColumn(style="bold #cc0000"),
        TextColumn(f"[#e8d5c4]{label}[/#e8d5c4]"),
        TimeElapsedColumn(),
        console=console,
    )


def results_table(title: str, columns: list, rows: list) -> Table:
    t = Table(
        title=title,
        box=box.MINIMAL_DOUBLE_HEAD,
        title_style="bold #cc0000",
        header_style="bold #ffffff",
        border_style="#7a5a4a",
        show_lines=False,
    )
    for col in columns:
        t.add_column(col, style="#e8d5c4")
    for row in rows:
        t.add_row(*[str(c) for c in row])
    return t


def risk_badge(score: float) -> str:
    if score >= 50:
        return "[bold #cc0000]CRITICAL[/bold #cc0000]"
    elif score >= 30:
        return "[bold #cc6600]HIGH[/bold #cc6600]"
    elif score >= 15:
        return "[bold #ccaa00]MEDIUM[/bold #ccaa00]"
    else:
        return "[bold #00cc44]LOW[/bold #00cc44]"


def summary_panel(target: str, score: float, findings: dict):
    badge = risk_badge(score)
    
    # Create structured key-value grid for metadata
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=2)
    
    grid.add_row("[#7a5a4a]Target Host[/#7a5a4a]", f"[bold #ffffff]{target}[/bold #ffffff]")
    grid.add_row("[#7a5a4a]Risk Rating[/#7a5a4a]", f"{score:.1f} ({badge})")
    grid.add_row("[#7a5a4a]Generated Reports[/#7a5a4a]", f"[#e8d5c4]HTML, JSON, Markdown[/#e8d5c4]")
    
    # Build list of key issues to render directly in the panel
    issues_list = []
    raw_findings = findings.get("findings", [])
    if raw_findings:
        for f in raw_findings[:8]:  # Limit to top 8 findings to prevent overflow
            issues_list.append(f"• {f}")
        if len(raw_findings) > 8:
            issues_list.append(f"• ... and {len(raw_findings) - 8} more findings.")
    else:
        issues_list.append("No critical risk signals flagged.")
        
    issues_text = Text("\n".join(issues_list), style="#e8d5c4")

    # Combine metadata grid and issues into panels
    body_table = Table.grid(expand=True)
    body_table.add_column()
    body_table.add_row(grid)
    body_table.add_row("\n[bold #cc0000]KEY RISK INDICATORS[/bold #cc0000]")
    body_table.add_row(issues_text)

    console.print()
    console.print(Panel(
        body_table,
        title=f"[bold #cc0000]▸ WRAITH-NET STRIKE SUMMARY — {target.upper()} ◂[/bold #cc0000]",
        border_style="#cc0000",
        box=box.ROUNDED,
        padding=(1, 3),
    ))
