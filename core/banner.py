import time

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core import __app_name__, __version__

console = Console()

_BANNER_ASCII = r"""
 █████╗ ██╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


def print_danger_banner(quick: bool = False) -> None:
    """
    Renders the intro banner + a short fake "boot sequence" for flavor.
    Pass quick=True (e.g. from a --no-banner-delay flag) to skip the
    artificial sleeps -- useful when scripting/automating scans.
    """
    cyber_text = Text()
    cyber_text.append("[!] CRITICAL THREAT INTELLIGENCE SYSTEM INITIALIZED\n", style="bold blink red")
    cyber_text.append("----------------------------------------------------------------------\n", style="bright_black")
    cyber_text.append(_BANNER_ASCII, style="bold red")
    cyber_text.append("\n----------------------------------------------------------------------\n", style="bright_black")
    cyber_text.append(f"[*] COMPILED STACK: PYTHON 3.13 | ENGINE CORE: OPENAI RECON\n", style="cyan")
    cyber_text.append(f"[*] SECURITY RUNTIME: ACTIVE CORE MATRIX\n", style="bold yellow")

    panel = Panel(
        Align.center(cyber_text),
        border_style="red",
        title=f"[bold white]⚔️ {__app_name__} VULNERABILITY MATRIX v{__version__} ⚔️[/bold white]",
        subtitle="[bold red]⚠️ AUTHORIZED CYBERSECURITY AUDITING ONLY ⚠️[/bold red]",
        expand=False,
    )

    console.print(panel)
    console.print()

    with console.status("[bold green]Loading operational system components...", spinner="dots"):
        time.sleep(0.0 if quick else 0.6)
        console.print("[cyan][+][/cyan] Network scanning modules linked successfully.")
        time.sleep(0.0 if quick else 0.4)
        console.print("[cyan][+][/cyan] AI patch pipeline ready.")
        time.sleep(0.0 if quick else 0.3)
    console.print()


def print_mini_banner() -> None:
    """A one-line, no-frills banner for non-interactive / scripted contexts."""
    console.print(f"[bold red]⚔️ {__app_name__} v{__version__}[/bold red] — [bright_black]authorized auditing only[/bright_black]")
