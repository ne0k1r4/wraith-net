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
    console.print(BANNER, style="bold #cc0000")
    console.print(f"  {TAGLINE}", style="#7a5a4a")
    console.print(f"  {AUTHOR}\n", style="#e8d5c4")


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
    body = Text()
    body.append(f"  Target  : ", style="bold #7a5a4a")
    body.append(f"{target}\n", style="bold #e8d5c4")
    body.append(f"  Risk    : ", style="bold #7a5a4a")
    body.append(f"{score:.1f}  ", style="bold #ffffff")
    console.print()
    console.print(Panel(
        body,
        title=f"[bold #cc0000]▸ WRAITH-NET REPORT — {target.upper()} ◂[/bold #cc0000]",
        subtitle=f"Risk Score: {score:.1f} — {badge}",
        border_style="#cc0000",
        padding=(1, 4),
    ))
