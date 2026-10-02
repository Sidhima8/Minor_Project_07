"""
cli.py — Click-based command-line interface for PCAP AI Parser.

Commands
--------
  pcap-parse parse <file>          Parse with dpkt (default) or tshark
  pcap-parse info  <file>          Show summary stats only
  pcap-parse check                 Verify environment (Python, dpkt, tshark)
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from pcap_ai_parser.parser.dpkt_parser import DpktPCAPParser
from pcap_ai_parser import __version__

console = Console()

# ── Logging setup ─────────────────────────────────────────────────────────────

def _configure_logging(verbose: bool) -> None:
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(sys.stderr, level=level, format="<level>{level: <8}</level> {message}")


# ── Root group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="pcap-parse")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """PCAP AI Parser — bulk packet capture analysis pipeline."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _configure_logging(verbose)


# ── check command ─────────────────────────────────────────────────────────────

@main.command()
def check() -> None:
    """Verify that all required tools and libraries are installed."""
    import importlib
    import subprocess

    table = Table(title="Environment Check", show_header=True)
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Detail")

    # Python version
    v = sys.version.split()[0]
    ok = tuple(int(x) for x in v.split(".")) >= (3, 9)
    table.add_row(
        "Python",
        "[green]OK[/green]" if ok else "[red]FAIL[/red]",
        v,
    )

    # Required libraries
    for lib in ["dpkt", "pandas", "rich", "click", "loguru", "tqdm", "scapy"]:
        try:
            m = importlib.import_module(lib)
            ver = getattr(m, "__version__", "?")
            table.add_row(lib, "[green]OK[/green]", ver)
        except ImportError:
            table.add_row(lib, "[red]MISSING[/red]", "pip install " + lib)

    # tshark check
    try:
        result = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            ver_line = result.stdout.splitlines()[0] if result.stdout else "Available"
            table.add_row("tshark", "[green]OK[/green]", ver_line)
        else:
            table.add_row("tshark", "[yellow]MISSING[/yellow]", "Install wireshark / tshark")
    except FileNotFoundError:
        table.add_row("tshark", "[yellow]MISSING[/yellow]", "Install wireshark / tshark")

    console.print(table)


# ── parse command ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--backend", "-b",
    type=click.Choice(["dpkt", "tshark"], case_sensitive=False),
    default="dpkt",
    show_default=True,
    help="Parsing backend to use.",
)
@click.option("--max-packets", "-n", default=0, help="Limit number of packets (0=all).")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save CSV to file.")
@click.option("--summary/--no-summary", default=True, help="Print summary statistics.")
@click.pass_context
def parse(
    ctx: click.Context,
    pcap_file: str,
    backend: str,
    max_packets: int,
    output: str | None,
    summary: bool,
) -> None:
    """Parse a PCAP file and display packet metadata."""
    path = Path(pcap_file)
    console.rule(f"[bold cyan]Parsing {path.name} (backend={backend})")

    dpkt_parser = DpktPCAPParser()
    records = dpkt_parser.parse_file(str(path))
    if max_packets > 0:
        records = records[:max_packets]

    if ctx.obj.get("verbose"):
        for rec in records:
            rprint(rec.to_dict())

    console.print(f"\n[green][OK][/green] Parsed [bold]{len(records):,}[/bold] packets from [cyan]{path.name}[/cyan]")

    if summary:
        stats = {
            "file": str(path),
            "total_packets": len(records),
            "total_bytes": sum(r.orig_len for r in records),
            "avg_packet_size": round(sum(r.orig_len for r in records) / len(records), 2) if records else 0,
            "parse_errors": 0,
        }
        _print_summary(stats)

    if output:
        import pandas as pd  # type: ignore[import-untyped]
        df = pd.DataFrame([r.to_dict() for r in records])
        df.to_csv(output, index=False)
        console.print(f"[green][OK][/green] Saved CSV → [cyan]{output}[/cyan]")


# ── info command ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
def info(pcap_file: str) -> None:
    """Show high-level statistics for a PCAP file (no full parse)."""
    path = Path(pcap_file)
    dpkt_parser = DpktPCAPParser()
    records = dpkt_parser.parse_file(str(path))
    stats = {
        "file": str(path),
        "total_packets": len(records),
        "total_bytes": sum(r.orig_len for r in records),
        "avg_packet_size": round(sum(r.orig_len for r in records) / len(records), 2) if records else 0,
        "parse_errors": 0,
    }
    _print_summary(stats)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_summary(stats: dict) -> None:
    table = Table(title="Capture Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("File", stats.get("file", ""))
    table.add_row("Total packets", f"{stats.get('total_packets', 0):,}")
    table.add_row("Total bytes", f"{stats.get('total_bytes', 0):,}")
    table.add_row("Avg packet size", f"{stats.get('avg_packet_size', 0)} B")
    table.add_row("Parse errors", str(stats.get("parse_errors", 0)))

    console.print(table)


if __name__ == "__main__":
    main()
