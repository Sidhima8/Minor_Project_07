# PacketParser-AI

> **Intelligent PCAP Payload Decoder and Forensic Analysis Platform**
>
> Minor Project — B.Tech (CSE / Cybersecurity), Batch 2023–27
> Supervisor: Mr. Mohd Asif Hajam

---

## Team

| Name | Roll No. |
|------|----------|
| Sidhima | 2023A7R011 |
| Raghav Sharma | 2023A7R026 |
| Rohinish Sharma | 2023A7R050 |
| Sarthak Singh | 2023A7R056 |

---

## What It Does

PacketParser-AI is a local-first forensic tool for analysing network packet captures (`.pcap` / `.pcapng`). It runs a full pipeline:

```
PCAP File
  --> Packet Parsing (dpkt / tshark)
  --> Byte Normalization (Hex, Dec, Bin, ASCII)
  --> Payload Decoding (Base64, URL-encode, Hex-escape -- recursive)
  --> Shannon Entropy Analysis
  --> IOC Extraction (IPs, URLs, Domains, Emails, Hashes, CVEs)
  --> Heuristic Risk Scoring (0-100, 5 severity levels)
  --> Web Dashboard  /  PDF + JSON Reports
```

---

## Quick Start

### 1. Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11+ | 3.13 recommended |
| uv | latest | `pip install uv` |
| Wireshark / tshark | 4.x | Optional (deep DPI backend) |

### 2. Install

```powershell
# Clone / open project directory
cd PCAP_AI_Parser

# Install all dependencies into .venv
uv sync

# Generate the synthetic attack-traffic demo capture
uv run python scripts/generate_sample_pcap.py
```

### 3. Launch the Web Dashboard

```powershell
uv run python main.py
```

Open **http://localhost:8000** in your browser.

- Drag & drop any `.pcap` / `.pcapng` file onto the upload zone, **or**
- Click **"Load Demo Sample"** to analyse the built-in attack traffic capture.

---

## CLI Reference

All commands are prefixed with `pcap-parse`. Run inside the project with `uv run pcap-parse <command>`.

### `check` — Environment verification

```powershell
uv run pcap-parse check
```

Verifies Python version, all required libraries, and tshark availability.

---

### `parse` — Parse a capture file

```powershell
uv run pcap-parse parse data/samples/sample.pcap
uv run pcap-parse parse data/samples/sample.pcap --backend tshark
uv run pcap-parse parse data/samples/sample.pcap --max-packets 50 --output packets.csv
```

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `dpkt` | Parsing engine: `dpkt` (fast, no install needed) or `tshark` (deep DPI, requires Wireshark) |
| `--max-packets` / `-n` | `0` (all) | Stop after N packets |
| `--output` / `-o` | — | Save parsed records to CSV |
| `--no-summary` | — | Skip summary statistics table |

---

### `info` — Quick summary stats

```powershell
uv run pcap-parse info data/samples/sample.pcap
```

Shows protocol distribution, top source IPs, packet/byte counts. No full parse.

---

### `inspect` — Deep-dive single packet

```powershell
uv run pcap-parse inspect data/samples/sample.pcap --packet 5
```

Displays for the chosen packet:
- L2/L3/L4 metadata panel
- Full hex dump (xxd format)
- Extracted printable strings
- Octet transformation table (Decimal / Binary / ASCII)
- Decoded encoding artifacts (Base64, URL, Hex-escape)
- Threat Intelligence panel: risk score, entropy, IOCs, findings

| Flag | Default | Description |
|------|---------|-------------|
| `--packet` / `-p` | `1` | Packet number (1-based) |

---

### `triage` — Full PCAP threat scan

```powershell
uv run pcap-parse triage data/samples/sample.pcap
uv run pcap-parse triage data/samples/sample.pcap --min-score 30
```

Scans every packet and prints:
1. Executive summary (severity breakdown, IOC count)
2. Flagged suspicious packets table (top 20)
3. Harvested IOCs table (IPs, URLs, Hashes, CVEs...)

| Flag | Default | Description |
|------|---------|-------------|
| `--min-score` / `-s` | `1` | Minimum risk score to show in flagged table |

---

### `report` — Generate PDF / JSON reports

```powershell
# Both formats
uv run pcap-parse report data/samples/sample.pcap --pdf --json

# PDF only, custom output directory
uv run pcap-parse report data/samples/sample.pcap --pdf --output-dir reports/
```

Outputs files to `output/` (or `--output-dir`):
- `<stem>_report.pdf` — multi-page ReportLab forensic report
- `<stem>_report.json` — structured machine-readable analysis

| Flag | Default | Description |
|------|---------|-------------|
| `--pdf` | off | Export PDF report |
| `--json` | off | Export JSON report |
| `--output-dir` / `-o` | `output/` | Destination directory |

---

### `web` — Launch the web dashboard (CLI shortcut)

```powershell
uv run pcap-parse web
uv run pcap-parse web --port 9000 --no-reload
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `8000` | Bind port |
| `--no-reload` | off | Disable hot-reload |

---

## Web Dashboard

| Section | Description |
|---------|-------------|
| Upload zone | Drag & drop PCAP or click to browse |
| Load Sample | Analyses built-in synthetic attack traffic |
| Metric cards | Total packets, payload packets, IOC count, Critical+High count |
| Protocol chart | Doughnut breakdown by protocol |
| Severity chart | Bar chart of CLEAN / LOW / MEDIUM / HIGH / CRITICAL counts |
| Flagged packets | Sortable table — click any row to open inspector modal |
| IOC Harvest | All extracted Indicators of Compromise |
| Packet Inspector | Hex dump, decoded artifacts, threat panel per packet |
| Export | Download PDF or JSON report from the top-right Export button |

---

## API Endpoints (FastAPI)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web dashboard (HTML) |
| `POST` | `/api/upload` | Upload & analyse a PCAP file |
| `POST` | `/api/load-sample` | Analyse the built-in sample PCAP |
| `GET` | `/api/analysis` | Return current session analysis JSON |
| `GET` | `/api/packets/{n}` | Full inspection data for packet #n |
| `GET` | `/api/export/pdf` | Download PDF report |
| `GET` | `/api/export/json` | Download JSON report |
| `GET` | `/docs` | Auto-generated Swagger UI |

---

## Project Structure

```
PCAP_AI_Parser/
|-- main.py                          # Server entry point (uvicorn)
|-- pyproject.toml                   # Dependencies & CLI entrypoint
|-- scripts/
|   `-- generate_sample_pcap.py      # Synthetic attack traffic generator
|-- data/samples/
|   `-- sample.pcap                  # Generated demo capture
|-- output/                          # Report output directory
|-- tests/
|   |-- test_dpkt_parser.py          # 41 tests
|   |-- test_analyzer.py             # 14 tests
|   |-- test_intelligence.py         # 15 tests
|   `-- test_reporting.py            # 3 tests
`-- src/pcap_ai_parser/
    |-- cli.py                       # Click CLI: check/parse/info/inspect/triage/report/web
    |-- models/packet.py             # PacketRecord dataclass
    |-- parser/
    |   |-- dpkt_parser.py           # Streaming PCAP parser (dpkt)
    |   `-- tshark_parser.py         # Deep DPI parser (tshark subprocess)
    |-- analyzer/
    |   |-- byte_normalizer.py       # Hex/Dec/Bin/ASCII normalization
    |   `-- decoder.py               # Recursive payload decoder (Base64, URL, Hex)
    |-- intelligence/
    |   |-- entropy.py               # Shannon entropy analysis
    |   |-- ioc_extractor.py         # IOC regex harvester
    |   `-- risk_scorer.py           # Heuristic risk scoring (0-100)
    |-- reporting/
    |   |-- json_exporter.py         # JSON report builder
    |   `-- pdf_generator.py         # PDF report (ReportLab)
    `-- web/
        |-- app.py                   # FastAPI application + REST API
        `-- templates/index.html     # Dark forensic dashboard (Tailwind + Chart.js)
```

---

## Risk Scoring Model

Packets are scored 0–100 and classified into five severity levels:

| Severity | Score Range | Colour |
|----------|------------|--------|
| CLEAN | 0 | Green |
| LOW | 1–24 | Cyan |
| MEDIUM | 25–49 | Yellow |
| HIGH | 50–74 | Red |
| CRITICAL | 75–100 | Dark Red |

**Scoring factors include:** suspicious ports (Telnet, FTP, Metasploit 4444, 1337), high entropy on non-TLS ports, plaintext credentials, HTTP Basic Auth, API key exposure, SQL injection patterns, XSS, path traversal, command injection, CVE references, crypto hashes in cleartext, obfuscated IOCs in decoded payloads.

---

## Running Tests

```powershell
uv run pytest
uv run pytest -v          # verbose
uv run pytest --tb=short  # with short traceback on failures
```

Expected: **72 tests pass** in under 1 second.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `dpkt` | Fast PCAP/PCAPng parsing |
| `fastapi` | REST API + web framework |
| `uvicorn` | ASGI server |
| `jinja2` | HTML templating |
| `reportlab` | PDF generation |
| `click` | CLI framework |
| `rich` | Terminal output formatting |
| `loguru` | Structured logging |
| `pandas` | CSV export |
| `tqdm` | Progress bars |

---

## Notes

- **Windows:** All console output uses ASCII-only symbols (no Unicode arrows/bullets) to avoid `cp1252` encoding errors in PowerShell.
- **tshark:** Auto-detected at `C:\Program Files\Wireshark\tshark.exe` on Windows. The `dpkt` backend is used by default and requires no external tools.
- **OneDrive sync:** If `uv add` fails with a ReadOnly error on `.venv`, use `uv pip install <pkg>` directly instead.
