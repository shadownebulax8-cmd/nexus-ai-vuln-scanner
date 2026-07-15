import asyncio
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from ai_engine.patch_generator import generate_remediation_patch
from config.settings import settings
from core import __app_name__, __version__
from core.banner import print_danger_banner, print_mini_banner
from core.network_scanner import VULNERABILITY_SIGNATURES, run_parallel_scan
from core.port_parser import parse_ports
from reporting.json_writer import export_json_report
from reporting.markdown_writer import export_vulnerability_report

console = Console()

app = typer.Typer(
    name="nexus-ai",
    help=f"⚔️ [bold red]{__app_name__}[/bold red] — async recon scanner with AI-assisted remediation.",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


class ReportFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    both = "both"


class PortPreset(str, Enum):
    quick = "quick"
    default = "default"
    full = "full"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold red]{__app_name__}[/bold red] v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show the application version and exit.",
    ),
) -> None:
    """
    Run [bold]nexus-ai scan <target> --help[/bold] for scanning options, or
    [bold]nexus-ai signatures[/bold] to see the built-in vulnerability database.
    """


def _print_summary_table(target: str, findings: List[Dict[str, Any]]) -> None:
    table = Table(title=f"Exposure Summary — {target}", header_style="bold red")
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("OWASP Category")
    table.add_column("Banner", overflow="fold")
    for f in findings:
        banner_text = f["banner_grabbed"]
        if len(banner_text) > 60:
            banner_text = banner_text[:57] + "..."
        table.add_row(str(f["port"]), f["service"], f["owasp_category"], banner_text or "-")
    console.print(table)


def _print_report_paths(md_path: Optional[str], json_path: Optional[str]) -> None:
    if md_path:
        console.print(f"[bold green][+][/bold green] Markdown report saved: [bold white]{md_path}[/bold white]")
    if json_path:
        console.print(f"[bold green][+][/bold green] JSON report saved: [bold white]{json_path}[/bold white]")
    console.print()


def _print_rollup(results: List[Dict[str, Any]]) -> None:
    if len(results) <= 1:
        return
    table = Table(title="Multi-Target Rollup", header_style="bold cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Open Ports", justify="right")
    style_map = {"clean": "green", "vulnerable": "red", "error": "yellow"}
    for r in results:
        style = style_map.get(r["status"], "white")
        table.add_row(r["target"], f"[{style}]{r['status']}[/{style}]", str(r["open_ports"]))
    console.print(table)


async def _scan_one_target(
    target: str,
    ports: List[int],
    api_key: Optional[str],
    model: str,
    timeout: float,
    concurrency: int,
    output_dir: str,
    fmt: ReportFormat,
    verbose: bool,
) -> Dict[str, Any]:
    console.print(f"[bold cyan][⚡][/bold cyan] Initiating assessment against: [bold white]{target}[/bold white]")
    console.print(
        f"[bold cyan][⚡][/bold cyan] Scanning depth: {len(ports)} ports | "
        f"timeout {timeout}s | concurrency {concurrency}\n"
    )

    start_time = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} ports"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"Scanning {target}", total=len(ports))

        def _on_port_done(_port: int, _result: Dict[str, Any]) -> None:
            progress.update(task_id, advance=1)

        open_findings = await run_parallel_scan(
            target,
            ports,
            timeout=timeout,
            banner_timeout=settings.BANNER_READ_TIMEOUT,
            max_concurrency=concurrency,
            on_port_done=_on_port_done,
        )

    duration = time.monotonic() - start_time

    if isinstance(open_findings, list) and len(open_findings) > 0 and "error" in open_findings[0]:
        console.print(f"[bold red]❌ Network Failure:[/bold red] {open_findings[0]['error']}\n")
        return {"target": target, "status": "error", "open_ports": 0}

    if not open_findings:
        console.print(
            f"[bold green]✔ Clean:[/bold green] Zero exposed surfaces on {target} "
            f"across {len(ports)} ports ({duration:.2f}s).\n"
        )
        md_path = (
            export_vulnerability_report(target, [], "Clean Scan", len(ports), duration, output_dir)
            if fmt in (ReportFormat.markdown, ReportFormat.both) else None
        )
        json_path = (
            export_json_report(target, [], "Clean Scan", len(ports), duration, output_dir)
            if fmt in (ReportFormat.json, ReportFormat.both) else None
        )
        _print_report_paths(md_path, json_path)
        return {"target": target, "status": "clean", "open_ports": 0}

    console.print(
        f"\n[bold yellow]⚠️ WARNING:[/bold yellow] Discovered "
        f"[bold red]{len(open_findings)}[/bold red] exposed entry point(s) on {target}."
    )
    console.print("-" * 72, style="bright_black")

    has_api = bool(api_key or settings.OPENAI_API_KEY)
    scan_mode = "AI-Assisted Autonomous Remediation" if has_api else "Signature-Based Local Fallback"

    processed_findings: List[Dict[str, Any]] = []
    for vuln in open_findings:
        console.print(f"[bold red][CRITICAL][/bold red] Port [bold white]{vuln['port']}[/bold white] ({vuln['service']})")
        console.print(f" ╰─► OWASP Mapping: [yellow]{vuln['owasp_category']}[/yellow]")
        if verbose:
            console.print(f" ╰─► Handshake Signature: [italic dim]{vuln['banner_grabbed']}[/italic dim]")
        console.print(" ╰─► Computing remediation...", style="cyan")

        patch = await generate_remediation_patch(vuln, api_key=api_key, model=model)
        vuln["patch"] = patch
        processed_findings.append(vuln)

        console.print(f"\n[green]{patch}[/green]")
        console.print("-" * 72, style="bright_black")

    _print_summary_table(target, processed_findings)

    md_path = (
        export_vulnerability_report(target, processed_findings, scan_mode, len(ports), duration, output_dir)
        if fmt in (ReportFormat.markdown, ReportFormat.both) else None
    )
    json_path = (
        export_json_report(target, processed_findings, scan_mode, len(ports), duration, output_dir)
        if fmt in (ReportFormat.json, ReportFormat.both) else None
    )
    _print_report_paths(md_path, json_path)

    return {"target": target, "status": "vulnerable", "open_ports": len(open_findings)}


@app.command()
def scan(
    targets: str = typer.Argument(
        ..., help="Target host/IP. Comma-separate multiple targets, e.g. 'example.com,10.0.0.5'."
    ),
    ports: Optional[str] = typer.Option(
        None, "--ports", "-p",
        help="Explicit ports/ranges, comma separated (e.g. '22,80,443' or '1-1024'). Overrides --preset.",
    ),
    preset: PortPreset = typer.Option(
        PortPreset.default, "--preset",
        help="Port preset: quick (8 ports), default (24 common ports), full (1-1024).",
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k", help="OpenAI API key, overrides .env / environment default."
    ),
    model: str = typer.Option(
        settings.OPENAI_MODEL, "--model", "-m", help="OpenAI model used for AI-assisted patch generation."
    ),
    timeout: float = typer.Option(
        settings.GLOBAL_TIMEOUT, "--timeout", "-t", help="Per-port connection timeout, in seconds."
    ),
    concurrency: int = typer.Option(
        settings.MAX_CONCURRENCY, "--concurrency", "-c", help="Maximum concurrent port probes."
    ),
    output_dir: str = typer.Option(
        settings.REPORT_OUTPUT_DIR, "--output", "-o", help="Directory to write report(s) into."
    ),
    fmt: ReportFormat = typer.Option(
        ReportFormat.markdown, "--format", "-f", help="Report format(s) to export."
    ),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Skip the animated intro banner (handy for CI/scripted runs)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show raw handshake banners in the live console output."
    ),
) -> None:
    """
    Run a full recon + AI-remediation sweep against one or more targets.

    [bold]Examples[/bold]

      nexus-ai scan example.com
      nexus-ai scan 192.168.1.10 --preset full --format both
      nexus-ai scan a.com,b.com -p 22,80,443 -k sk-...
    """
    try:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        if not target_list:
            console.print("[bold red]❌ Input Error:[/bold red] No target provided.")
            raise typer.Exit(code=1)

        if ports:
            port_list = parse_ports(ports)
        elif preset == PortPreset.quick:
            port_list = settings.QUICK_PORTS
        elif preset == PortPreset.full:
            port_list = parse_ports(settings.FULL_PORTS_RANGE)
        else:
            port_list = settings.DEFAULT_PORTS
    except ValueError as e:
        console.print(f"[bold red]❌ Input Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if no_banner:
        print_mini_banner()
    else:
        print_danger_banner()

    async def _runner() -> None:
        results = []
        for target in target_list:
            result = await _scan_one_target(
                target, port_list, api_key, model, timeout, concurrency, output_dir, fmt, verbose
            )
            results.append(result)
        _print_rollup(results)

    try:
        asyncio.run(_runner())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        raise typer.Exit(code=130)


@app.command()
def signatures() -> None:
    """List the built-in port → service → OWASP signature database used for triage."""
    table = Table(title=f"{__app_name__} Signature Database", header_style="bold red")
    table.add_column("Port", justify="right")
    table.add_column("Service")
    table.add_column("OWASP Category")
    table.add_column("Typical Exposure")
    for port, info in sorted(VULNERABILITY_SIGNATURES.items()):
        table.add_row(str(port), info["service"], info["owasp"], info["issue"])
    console.print(table)


@app.command()
def banner() -> None:
    """Print the intro banner without running a scan."""
    print_danger_banner()


@app.command()
def version() -> None:
    """Show the application version."""
    console.print(f"[bold red]{__app_name__}[/bold red] v{__version__}")


if __name__ == "__main__":
    app()
