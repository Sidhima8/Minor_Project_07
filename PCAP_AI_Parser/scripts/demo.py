"""
demo.py - One-shot PacketParser-AI demonstration script.

Runs the full pipeline end-to-end:
  1. Generates synthetic attack-traffic sample PCAP
  2. Runs CLI triage over the capture
  3. Exports PDF + JSON forensic reports to output/
  4. Prints instructions to open the web dashboard

Usage:
    uv run python scripts/demo.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "samples" / "sample.pcap"


def run(args: list[str], label: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"{'─' * 60}")
    result = subprocess.run(
        [sys.executable, "-m", "pcap_ai_parser.cli"] + args,
        cwd=ROOT,
    )
    if result.returncode != 0:
        print(f"[WARN] Step exited with code {result.returncode}")


def main() -> None:
    print("="* 60)
    print("  PacketParser-AI  --  Full Pipeline Demo")
    print("="* 60)

    # Step 1: Generate sample PCAP
    print("\n[1/4] Generating synthetic attack-traffic capture...")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_sample_pcap.py")],
        cwd=ROOT,
        check=True,
    )

    if not SAMPLE.exists():
        print("ERROR: sample.pcap was not created. Aborting.")
        sys.exit(1)

    # Step 2: Environment check
    run(["check"], "[2/4] Environment verification")

    # Step 3: Triage
    run(["triage", str(SAMPLE)], "[3/4] Forensic threat triage")

    # Step 4: Export reports
    run(
        ["report", str(SAMPLE), "--pdf", "--json"],
        "[4/4] Generating PDF + JSON forensic reports",
    )

    print("\n" + "=" * 60)
    print("  Demo complete!")
    print(f"  Reports saved to: {ROOT / 'output'}")
    print("")
    print("  To open the web dashboard:")
    print("    uv run python main.py")
    print("  Then visit: http://localhost:8000")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
