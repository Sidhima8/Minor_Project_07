"""
cli.py — Click-based command-line interface for PCAP AI Parser.

Commands
--------
  pcap-parse parse <file>          Parse with dpkt (default) or tshark
  pcap-parse info  <file>          Show summary stats only
  pcap-parse check                  Verify environment (Python, dpkt, tshark)
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from rich.panel import Panel

from pcap_ai_parser.analyzer import PayloadDecoder, normalize_payload
from pcap_ai_parser.intelligence import HeuristicRiskScorer, analyze_entropy
from pcap_ai_parser.parser.dpkt_parser import DpktParser
from pcap_ai_parser.parser.tshark_parser import TsharkParser
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

    table = Table(title="Environment Check", show_header=True)
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Detail")

    # Python version
    v = sys.version.split()[0]
    ok = tuple(int(x) for x in v.split(".")) >= (3, 11)
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

    # tshark
    tshark_bin = TsharkParser.resolve_binary()
    if tshark_bin:
        import subprocess
        result = subprocess.run([tshark_bin, "--version"], capture_output=True, text=True)
        ver_line = result.stdout.splitlines()[0] if result.stdout else "?"
        table.add_row("tshark", "[green]OK[/green]", ver_line)
    else:
        table.add_row(
            "tshark",
            "[yellow]MISSING[/yellow]",
            "Install Wireshark (https://www.wireshark.org/)" if sys.platform == "win32" else "sudo apt install tshark / pacman -S wireshark-cli",
        )

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

    records = []

    if backend == "dpkt":
        with DpktParser(path, max_packets=max_packets) as parser:
            for rec in parser.parse():
                records.append(rec)
                if ctx.obj.get("verbose"):
                    rprint(str(rec))
            stats = parser.summary()

    elif backend == "tshark":
        if not TsharkParser.check_available():
            console.print("[red]tshark not found.[/red] Install: sudo pacman -S wireshark-cli")
            raise SystemExit(1)
        with TsharkParser(path) as parser:
            for rec in parser.parse():
                if max_packets and len(records) >= max_packets:
                    break
                records.append(rec)
                if ctx.obj.get("verbose"):
                    rprint(str(rec))
        stats = {
            "file": str(path),
            "total_packets": len(records),
            "total_bytes": sum(r.wire_length for r in records),
        }

    console.print(f"\n[green][OK][/green] Parsed [bold]{len(records):,}[/bold] packets from [cyan]{path.name}[/cyan]")

    if summary and backend == "dpkt":
        _print_summary(stats)

    if output:
        import pandas as pd
        df = pd.DataFrame([r.to_dict() for r in records])
        df.to_csv(output, index=False)
        console.print(f"[green][OK][/green] Saved CSV -> [cyan]{output}[/cyan]")


# ── info command ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
def info(pcap_file: str) -> None:
    """Show high-level statistics for a PCAP file (no full parse)."""
    path = Path(pcap_file)
    with DpktParser(path) as parser:
        for _ in parser.parse():
            pass
        _print_summary(parser.summary())


# ── inspect command ───────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--packet", "-p", "packet_num", type=int, default=1, help="Packet number to inspect (1-based).")
def inspect(pcap_file: str, packet_num: int) -> None:
    """Deep-dive byte inspection for a specific packet (Hex, Dec, Bin, ASCII, Decoders)."""
    path = Path(pcap_file)
    target_rec = None

    with DpktParser(path) as parser:
        for rec in parser.parse():
            if rec.packet_number == packet_num:
                target_rec = rec
                break

    if target_rec is None:
        console.print(f"[red]Packet #{packet_num} not found in {path.name}[/red]")
        return

    # Header Panel
    src = f"{target_rec.src_ip}:{target_rec.src_port}" if target_rec.src_port else target_rec.src_ip
    dst = f"{target_rec.dst_ip}:{target_rec.dst_port}" if target_rec.dst_port else target_rec.dst_ip
    hdr_info = (
        f"[bold]Packet #[/bold]{target_rec.packet_number}  |  "
        f"[bold]Proto:[/bold] {target_rec.transport_proto or target_rec.network_proto} ({target_rec.app_proto or 'Unknown App'})  |  "
        f"[bold]Size:[/bold] {target_rec.wire_length} B\n"
        f"[bold]Flow:[/bold] {src} -> {dst}\n"
        f"[bold]Flags:[/bold] {target_rec.tcp_flags or 'N/A'}  |  "
        f"[bold]Payload Length:[/bold] {target_rec.payload_length} bytes"
    )
    console.print(Panel(hdr_info, title=f"Packet #{target_rec.packet_number} Metadata", border_style="cyan"))

    artifacts = []
    if target_rec.payload:
        # Byte normalization
        norm = normalize_payload(target_rec.payload)

        # 1. Hex Dump
        console.print(Panel(norm.hex_dump, title="Hex Dump (Offset | Hex Octets | ASCII)", border_style="green"))

        # 2. Extracted strings
        if norm.extracted_strings:
            str_display = "\n".join(f"- {s}" for s in norm.extracted_strings)
            console.print(Panel(str_display, title="Extracted Printable Strings", border_style="blue"))

        # 3. Stream representations preview
        stream_table = Table(title="Octet Transformations Preview", show_header=True)
        stream_table.add_column("Format", style="bold")
        stream_table.add_column("Representation (first 32 octets)")

        dec_preview = " ".join(norm.decimal_stream.split()[:32])
        bin_preview = " ".join(norm.binary_stream.split()[:16])

        stream_table.add_row("Decimal (0-255)", dec_preview + ("..." if norm.total_bytes > 32 else ""))
        stream_table.add_row("Binary (8-bit)", bin_preview + ("..." if norm.total_bytes > 16 else ""))
        stream_table.add_row("ASCII Text", norm.ascii_text[:80] + ("..." if len(norm.ascii_text) > 80 else ""))
        console.print(stream_table)

        # 4. Decoders
        decoder = PayloadDecoder()
        artifacts = decoder.decode_all(target_rec.payload)
        if artifacts:
            dec_table = Table(title="Decoded Encodings Discovered", show_header=True, header_style="bold yellow")
            dec_table.add_column("Encoding")
            dec_table.add_column("Original")
            dec_table.add_column("Decoded Text")
            for art in artifacts:
                dec_table.add_row(art.encoding, art.original[:40], art.decoded_text[:60])
            console.print(dec_table)
    else:
        console.print("[dim yellow]No application payload present in this packet (0 payload bytes).[/dim yellow]")

    # 5. Risk Assessment & Threat Intelligence
    scorer = HeuristicRiskScorer()
    decoded_texts = [a.decoded_text for a in artifacts]
    assessment = scorer.evaluate(target_rec, decoded_texts=decoded_texts)

    color_map = {
        "CLEAN": "green",
        "LOW": "cyan",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }
    sev_color = color_map.get(assessment.severity, "white")
    threat_lines = [
        f"[bold]Risk Score:[/bold] [{sev_color}]{assessment.score}/100 ({assessment.severity})[/{sev_color}]  |  "
        f"[bold]Shannon Entropy:[/bold] {assessment.entropy:.4f} bits/byte  |  "
        f"[bold]IOCs Harvested:[/bold] {len(assessment.iocs)}"
    ]
    if assessment.findings:
        threat_lines.append("\n[bold]Findings:[/bold]")
        for f in assessment.findings:
            threat_lines.append(f"  - {f}")
    if assessment.iocs:
        threat_lines.append("\n[bold]Harvested Indicators of Compromise (IOCs):[/bold]")
        for ioc in assessment.iocs:
            threat_lines.append(f"  - [{ioc.ioc_type}] {ioc.value}")

    console.print(Panel("\n".join(threat_lines), title="Threat Intelligence & Heuristic Risk Analysis", border_style=sev_color))


# ── triage command ────────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--min-score", "-s", type=int, default=1, help="Minimum risk score to display in suspicious table (default: 1).")
def triage(pcap_file: str, min_score: int) -> None:
    """Run automated threat intelligence, entropy, and risk scoring triage over PCAP."""
    path = Path(pcap_file)
    console.rule(f"[bold red]Forensic Threat Triage: {path.name}[/bold red]")

    scorer = HeuristicRiskScorer()
    decoder = PayloadDecoder()

    total_packets = 0
    total_payloads = 0
    severity_counts = {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    suspicious_records = []
    aggregated_iocs = {}

    with DpktParser(path) as parser:
        for rec in parser.parse():
            total_packets += 1
            if rec.payload:
                total_payloads += 1

            artifacts = decoder.decode_all(rec.payload) if rec.payload else []
            decoded_texts = [a.decoded_text for a in artifacts]
            assessment = scorer.evaluate(rec, decoded_texts=decoded_texts)

            severity_counts[assessment.severity] = severity_counts.get(assessment.severity, 0) + 1

            if assessment.score >= min_score:
                suspicious_records.append((rec, assessment))

            for ioc in assessment.iocs:
                key = (ioc.ioc_type, ioc.value)
                if key not in aggregated_iocs:
                    aggregated_iocs[key] = []
                aggregated_iocs[key].append(rec.packet_number)

    # 1. Executive Summary Table
    sum_table = Table(title="Triage Executive Summary", show_header=True)
    sum_table.add_column("Category")
    sum_table.add_column("Count", justify="right")

    sum_table.add_row("Total Packets Analyzed", f"{total_packets:,}")
    sum_table.add_row("Packets with Application Payloads", f"{total_payloads:,}")
    sum_table.add_row("[green]Clean Packets[/green]", f"{severity_counts.get('CLEAN', 0):,}")
    sum_table.add_row("[cyan]Low Risk[/cyan]", f"{severity_counts.get('LOW', 0):,}")
    sum_table.add_row("[yellow]Medium Risk[/yellow]", f"{severity_counts.get('MEDIUM', 0):,}")
    sum_table.add_row("[red]High Risk[/red]", f"{severity_counts.get('HIGH', 0):,}")
    sum_table.add_row("[bold red]Critical Threat[/bold red]", f"{severity_counts.get('CRITICAL', 0):,}")
    sum_table.add_row("Unique IOCs Harvested", f"{len(aggregated_iocs):,}")
    console.print(sum_table)

    # 2. Flagged Packets Table
    if suspicious_records:
        flagged_table = Table(title=f"Flagged Suspicious Packets (Risk Score >= {min_score})", show_header=True)
        flagged_table.add_column("Pkt #", justify="right")
        flagged_table.add_column("Proto")
        flagged_table.add_column("Flow")
        flagged_table.add_column("Score", justify="right")
        flagged_table.add_column("Severity")
        flagged_table.add_column("Primary Findings")

        color_map = {"CLEAN": "green", "LOW": "cyan", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}

        for rec, assess in suspicious_records[:20]:
            src = f"{rec.src_ip}:{rec.src_port}" if rec.src_port else rec.src_ip
            dst = f"{rec.dst_ip}:{rec.dst_port}" if rec.dst_port else rec.dst_ip
            flow = f"{src} -> {dst}"
            col = color_map.get(assess.severity, "white")
            findings_str = "; ".join(assess.findings[:2]) if assess.findings else "N/A"
            flagged_table.add_row(
                str(rec.packet_number),
                rec.transport_proto or rec.network_proto,
                flow,
                str(assess.score),
                f"[{col}]{assess.severity}[/{col}]",
                findings_str,
            )
        console.print(flagged_table)
        if len(suspicious_records) > 20:
            console.print(f"[dim]Showing top 20 of {len(suspicious_records)} flagged packets.[/dim]")
    else:
        console.print("[green]No packets exceeded the risk threshold.[/green]")

    # 3. Harvested IOCs Table
    if aggregated_iocs:
        ioc_table = Table(title="Harvested Indicators of Compromise (IOCs)", show_header=True)
        ioc_table.add_column("IOC Type", style="bold")
        ioc_table.add_column("Extracted Value")
        ioc_table.add_column("Found in Packets", justify="right")

        for (ioc_type, val), pkts in list(aggregated_iocs.items())[:25]:
            pkt_str = ", ".join(f"#{p}" for p in pkts[:5]) + ("..." if len(pkts) > 5 else "")
            ioc_table.add_row(ioc_type, val, pkt_str)

        console.print(ioc_table)


# ── web command ──────────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host.")
@click.option("--port", default=8000, show_default=True, help="Bind port.")
@click.option("--no-reload", is_flag=True, help="Disable auto-reload.")
def web(host: str, port: int, no_reload: bool) -> None:
    """Launch the PacketParser-AI web dashboard (FastAPI + Chart.js)."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed.[/red] Run: uv pip install uvicorn")
        raise SystemExit(1)

    console.print(
        f"[bold cyan]PacketParser-AI Dashboard[/bold cyan] "
        f"starting at [underline]http://{host}:{port}[/underline]\n"
        "[dim]Press Ctrl+C to stop.[/dim]"
    )
    uvicorn.run(
        "pcap_ai_parser.web.app:app",
        host=host,
        port=port,
        reload=not no_reload,
        reload_dirs=["src"],
    )


# ── report command ────────────────────────────────────────────────────────────

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--pdf", "export_pdf", is_flag=True, default=False, help="Export PDF report.")
@click.option("--json", "export_json_flag", is_flag=True, default=False, help="Export JSON report.")
@click.option("--output-dir", "-o", type=click.Path(), default="output", show_default=True,
              help="Directory to save reports.")
def report(pcap_file: str, export_pdf: bool, export_json_flag: bool, output_dir: str) -> None:
    """Generate PDF and/or JSON forensic reports for a PCAP file."""
    from pcap_ai_parser.reporting import build_analysis_payload, export_json, generate_pdf_report

    if not export_pdf and not export_json_flag:
        console.print("[yellow]Specify at least --pdf or --json.[/yellow]")
        raise SystemExit(1)

    path = Path(pcap_file)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.rule(f"[bold cyan]Generating report for {path.name}[/bold cyan]")

    records = []
    stats = {}
    with DpktParser(path) as parser:
        for rec in parser.parse():
            records.append(rec)
        stats = parser.summary()

    analysis = build_analysis_payload(records, path.name, stats=stats)
    stem = path.stem

    if export_pdf:
        pdf_path = out_dir / f"{stem}_report.pdf"
        generate_pdf_report(analysis, pdf_path)
        console.print(f"[green][OK][/green] PDF report saved -> [cyan]{pdf_path}[/cyan]")

    if export_json_flag:
        json_path = out_dir / f"{stem}_report.json"
        export_json(analysis, json_path)
        console.print(f"[green][OK][/green] JSON report saved -> [cyan]{json_path}[/cyan]")


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

    if proto_dist := stats.get("proto_distribution"):
        t2 = Table(title="Protocol Distribution")
        t2.add_column("Protocol")
        t2.add_column("Packets", justify="right")
        for proto, count in proto_dist.items():
            t2.add_row(proto, str(count))
        console.print(t2)

    if top_src := stats.get("top_src_ips"):
        t3 = Table(title="Top Source IPs")
        t3.add_column("IP")
        t3.add_column("Packets", justify="right")
        for ip, count in list(top_src.items())[:10]:
            t3.add_row(ip, str(count))
        console.print(t3)
