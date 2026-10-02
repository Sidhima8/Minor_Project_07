# PCAP AI Parser

> AI-powered bulk PCAP analysis pipeline using `dpkt` and `tshark`.
> PacketParser-AI parses raw PCAP files, decodes headers and application payloads, normalizes binary data into printable text, and extracts statistical features for machine learning triage.

## Project Structure

```
PCAP_AI_Parser/
├── src/
│   └── pcap_ai_parser/
│       ├── __init__.py
│       ├── cli.py              # Click CLI entry-point
|       ├── payload_cli.py      # Payload triage CLI
│       ├── parser/
│       │   ├── __init__.py
│       │   ├── dpkt_parser.py  # dpkt-based fast parser
│       │   ├── payload_extractor.py      # L4/L7 payload decoder
│       │   └── tshark_parser.py # tshark subprocess parser
│       ├── models/
│       │   ├── __init__.py
│       │   └── packet.py       # Packet dataclass
│       └── utils/
│           ├── __init__.py
│           └── logging.py      # Loguru setup
│           └── metrics.py                # Shannon entropy & ASCII ratios
│           └── normalizer.py             # Binary-to-printable text & hex dumper
├── data/
│   └── samples/                # Place .pcap/.pcapng files here (git-ignored)
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   └── test_dpkt_parser.py
│   └── test_dpkt_payload.py              # Payload triage end-to-end tests
│   ├── test_payload_extraction.py        # Protocol decoder tests
│   └── test_normalization.py             # Text normalization & metric tests
├── scripts/
│   └── generate_sample_pcap.py # Helper to generate synthetic test PCAPs
│   └── generate_payload_normalisation_pcap.py # Multi-protocol payload generator
├── output/                     # Parsed output (git-ignored)
├── .gitignore
├── pyproject.toml
└── README.md
```

## Quick Start

### 1. Install dependencies

```bash
# Install uv (if not present)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install all deps
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### 2. Install tshark (system package)

```bash
# Arch / Manjaro
sudo pacman -S wireshark-cli

# Ubuntu / Debian
sudo apt install tshark

# macOS
brew install wireshark
```

### 3. Parse a PCAP file

```bash
# Quick parse with dpkt (fastest)
pcap-parse parse data/samples/sample.pcap

# Parse with tshark backend
pcap-parse parse --backend tshark data/samples/sample.pcap

# Generate a synthetic sample PCAP for testing
python scripts/generate_sample_pcap.py

# Generate Week 2 multi-protocol payload PCAP (HTTP, DNS, TLS, Shellcode, ICMP)
python scripts/generate_payload_normalisation_pcap.py
```

### 4. Run tests

```bash
pytest -v

# Verify system environment
python -m pcap_ai_parser.cli check

# Parse PCAP file with dpkt backend
python -m pcap_ai_parser.cli parse data/samples/sample.pcap

# Display capture summary statistics
python -m pcap_ai_parser.cli info data/samples/sample.pcap

# Print payload normalization & triage report
python -m pcap_ai_parser.payload_cli data/samples/sample.pcap

# Export structured JSON report for ML models
python -m pcap_ai_parser.payload_cli data/samples/sample.pcap --json

```

## Architecture

```
PCAP file
    │
    ▼
┌─────────────────────────────────┐
│         Parser Layer            │
│  ┌─────────────┐ ┌───────────┐  │
│  │ dpkt Parser │ │  tshark   │  │
│  │  (fast I/O) │ │ (deep DPI)│  │
│  └──────┬──────┘ └─────┬─────┘  │
└─────────┼──────────────┼────────┘
          │              │
          ▼              ▼
      PacketRecord dataclass (normalised)
          │
          ▼
      pandas DataFrame
          │
          ▼
┌────────────────────────────────────────┐
│     Payload Extraction & Normalizer    │
│  ┌──────────────┐ ┌─────────────────┐  │
│  │L4/L7 Decoder │ │ Hex Escaper &   │  │
│  │(HTTP,DNS,TLS)│ │ Normalizer      │  │
│  └──────┬───────┘ └─────┬───────────┘  │
└─────────┼───────────────┼──────────────┘
          │               │
          ▼               ▼
Statistical Payload Feature Calculation
(Shannon Entropy, ASCII Ratio & Unique Byte Ratio)
                  │
                  ▼
JSON / CSV Export for ML Triage & Forensic Analysis
                  │
                  ▼
      AI Analysis Layer (Phase 2)
```

## Development

```bash
# Linting
ruff check src/ tests/

# Type checking
mypy src/

# Coverage report
pytest --cov=pcap_ai_parser --cov-report=html
```
