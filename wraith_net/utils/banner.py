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
        console.print(BANNER, style="bold #bd93f9")  # Purple
        console.print(f"  {TAGLINE}", style="#6272a4")  # Grey
        console.print(f"  {AUTHOR}\n", style="#f8f8f2")  # White
        return

    # Otherwise, play cool startup animations
    banner_lines = BANNER.strip("\n").split("\n")
    for line in banner_lines:
        console.print(line, style="bold #bd93f9")
        time.sleep(0.03)
    
    tagline_text = f"  {TAGLINE}"
    for char in tagline_text:
        console.print(char, style="#6272a4", end="")
        time.sleep(0.008)
    console.print()
    
    author_text = f"  {AUTHOR}\n"
    for char in author_text:
        console.print(char, style="#f8f8f2", end="")
        time.sleep(0.006)


def section(title: str):
    console.print(f"\n[bold #bd93f9]┌─[ [bold #f8f8f2]{title}[/bold #f8f8f2] ][/bold #bd93f9]")


def ok(msg: str):
    console.print(f"[bold #50fa7b]  ✔[/bold #50fa7b] [{S['data']}]{msg}[/{S['data']}]")


def warn(msg: str):
    console.print(f"[bold #f1fa8c]  ⚠[/bold #f1fa8c] [{S['data']}]{msg}[/{S['data']}]")


def err(msg: str):
    console.print(f"[bold #ff5555]  ✘[/bold #ff5555] [{S['data']}]{msg}[/{S['data']}]")


def info(msg: str):
    console.print(f"[#6272a4]  ›[/#6272a4] [{S['data']}]{msg}[/{S['data']}]")


def get_spinner(label: str) -> Progress:
    return Progress(
        SpinnerColumn(style="bold #bd93f9"),
        TextColumn(f"[#f8f8f2]{label}[/#f8f8f2]"),
        TimeElapsedColumn(),
        console=console,
    )


def results_table(title: str, columns: list, rows: list) -> Table:
    t = Table(
        title=title,
        box=box.MINIMAL_DOUBLE_HEAD,
        title_style="bold #bd93f9",
        header_style="bold #ff79c6",
        border_style="#6272a4",
        show_lines=False,
    )
    for col in columns:
        t.add_column(col, style="#f8f8f2")
    for row in rows:
        t.add_row(*[str(c) for c in row])
    return t


def risk_badge(score: float) -> str:
    if score >= 50:
        return "[bold #ff5555]CRITICAL[/bold #ff5555]"
    elif score >= 30:
        return "[bold #ffb86c]HIGH[/bold #ffb86c]"
    elif score >= 15:
        return "[bold #f1fa8c]MEDIUM[/bold #f1fa8c]"
    else:
        return "[bold #50fa7b]LOW[/bold #50fa7b]"


def summary_panel(target: str, score: float, findings: dict):
    badge = risk_badge(score)
    
    # Create structured key-value grid for metadata
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=2)
    
    grid.add_row("[#6272a4]Target Host[/#6272a4]", f"[bold #f8f8f2]{target}[/bold #f8f8f2]")
    grid.add_row("[#6272a4]Risk Rating[/#6272a4]", f"{score:.1f} ({badge})")
    grid.add_row("[#6272a4]Generated Reports[/#6272a4]", f"[#f8f8f2]HTML, JSON, Markdown[/#f8f8f2]")
    
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
        
    issues_text = Text("\n".join(issues_list), style="#f8f8f2")

    # Combine metadata grid and issues into panels
    body_table = Table.grid(expand=True)
    body_table.add_column()
    body_table.add_row(grid)
    body_table.add_row("\n[bold #ff79c6]KEY RISK INDICATORS[/bold #ff79c6]")
    body_table.add_row(issues_text)

    console.print()
    console.print(Panel(
        body_table,
        title=f"[bold #bd93f9]▸ WRAITH-NET STRIKE SUMMARY — {target.upper()} ◂[/bold #bd93f9]",
        border_style="#bd93f9",
        box=box.ROUNDED,
        padding=(1, 3),
    ))
