"""
app.py — FastAPI backend application for PacketParser-AI Web Dashboard.
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from pcap_ai_parser.analyzer import (
    PayloadDecoder,
    normalize_payload,
)
from pcap_ai_parser.intelligence import HeuristicRiskScorer
from pcap_ai_parser.models.packet import PacketRecord
from pcap_ai_parser.parser.dpkt_parser import DpktParser
from pcap_ai_parser.reporting import (
    build_analysis_payload,
    export_json,
    generate_pdf_report,
)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="PacketParser-AI",
    description="Intelligent PCAP Payload Decoder and Text Normalizer",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# In-memory session store for single-analyst local triage
CURRENT_SESSION: dict[str, Any] = {
    "filename": None,
    "analysis": None,
    "raw_records": {},
}


def _analyze_pcap_file(pcap_path: Path) -> dict[str, Any]:
    """Parse PCAP file and run full forensics and intelligence pipelines."""
    records: list[PacketRecord] = []
    stats = {}

    with DpktParser(pcap_path) as parser:
        for rec in parser.parse():
            records.append(rec)
        stats = parser.summary()

    analysis = build_analysis_payload(records, str(pcap_path.name), stats=stats)

    # Store in memory for instant packet lookup
    CURRENT_SESSION["filename"] = pcap_path.name
    CURRENT_SESSION["analysis"] = analysis
    CURRENT_SESSION["raw_records"] = {rec.packet_number: rec for rec in records}

    return analysis


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Render main web dashboard."""
    has_data = CURRENT_SESSION["analysis"] is not None
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "has_data": has_data,
            "filename": CURRENT_SESSION["filename"],
        },
    )


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload and process a PCAP / PCAPng capture file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(
            status_code=400,
            detail="Unsupported format. Please upload a .pcap, .pcapng, or .cap file.",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        analysis = _analyze_pcap_file(tmp_path)
        CURRENT_SESSION["filename"] = file.filename
        analysis["metadata"]["source_file"] = file.filename
        return analysis
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP: {exc}") from exc
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


@app.post("/api/load-sample")
async def load_sample_pcap():
    """Load the built-in synthetic attack sample PCAP for demonstration."""
    # Find sample.pcap in data/samples
    candidates = [
        Path.cwd() / "data" / "samples" / "sample.pcap",
        BASE_DIR.parents[2] / "data" / "samples" / "sample.pcap",
    ]
    sample_file = None
    for cand in candidates:
        if cand.exists():
            sample_file = cand
            break

    if not sample_file:
        raise HTTPException(
            status_code=404,
            detail="Sample PCAP file not found. Run scripts/generate_sample_pcap.py first.",
        )

    try:
        analysis = _analyze_pcap_file(sample_file)
        return analysis
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse sample: {exc}") from exc


@app.get("/api/analysis")
async def get_current_analysis():
    """Return the currently loaded analysis data."""
    if not CURRENT_SESSION["analysis"]:
        raise HTTPException(status_code=404, detail="No PCAP has been analyzed yet.")
    return CURRENT_SESSION["analysis"]


@app.get("/api/packets/{packet_number}")
async def get_packet_inspection(packet_number: int):
    """
    Return comprehensive multi-base byte representations,
    decoded payloads, and threat analysis for a specific packet.
    """
    rec: PacketRecord | None = CURRENT_SESSION["raw_records"].get(packet_number)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Packet #{packet_number} not found.")

    # 1. Byte normalization
    norm = normalize_payload(rec.payload)

    # 2. Decoding
    decoder = PayloadDecoder()
    artifacts = decoder.decode_all(rec.payload) if rec.payload else []
    decoded_texts = [a.decoded_text for a in artifacts]

    # 3. Threat Assessment
    scorer = HeuristicRiskScorer()
    assessment = scorer.evaluate(rec, decoded_texts=decoded_texts)

    return {
        "packet_number": rec.packet_number,
        "timestamp": rec.timestamp,
        "protocol": rec.transport_proto or rec.network_proto,
        "app_proto": rec.app_proto or "Unknown",
        "wire_length": rec.wire_length,
        "payload_length": rec.payload_length,
        "src": f"{rec.src_ip}:{rec.src_port}" if rec.src_port else rec.src_ip,
        "dst": f"{rec.dst_ip}:{rec.dst_port}" if rec.dst_port else rec.dst_ip,
        "tcp_flags": rec.tcp_flags,
        "byte_normalization": norm.to_dict(),
        "decoded_artifacts": [a.to_dict() for a in artifacts],
        "threat_assessment": assessment.to_dict(),
    }


@app.get("/api/export/pdf")
async def export_pdf():
    """Download PDF forensic report for current analysis."""
    if not CURRENT_SESSION["analysis"]:
        raise HTTPException(status_code=400, detail="No active analysis to export.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp_path = Path(tmp.name)

    try:
        generate_pdf_report(CURRENT_SESSION["analysis"], tmp_path)
        with open(tmp_path, "rb") as f:
            pdf_bytes = f.read()

        filename = f"PacketParser_Report_{CURRENT_SESSION['filename'] or 'capture'}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


@app.get("/api/export/json")
async def export_json_report():
    """Download structured JSON report for current analysis."""
    if not CURRENT_SESSION["analysis"]:
        raise HTTPException(status_code=400, detail="No active analysis to export.")

    filename = f"PacketParser_Report_{CURRENT_SESSION['filename'] or 'capture'}.json"
    return Response(
        content=export_json_content(CURRENT_SESSION["analysis"]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def export_json_content(data: dict) -> str:
    import json
    return json.dumps(data, indent=2, ensure_ascii=False)
