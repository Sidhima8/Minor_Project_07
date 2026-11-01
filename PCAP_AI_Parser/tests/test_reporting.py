"""
test_reporting.py — unit tests for JSON export and PDF forensic report generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pcap_ai_parser.models.packet import PacketRecord
from pcap_ai_parser.reporting.json_exporter import (
    build_analysis_payload,
    export_json,
)
from pcap_ai_parser.reporting.pdf_generator import generate_pdf_report


@pytest.fixture
def sample_records() -> list[PacketRecord]:
    return [
        PacketRecord(
            packet_number=1,
            timestamp=1700000000.0,
            wire_length=64,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=54000,
            dst_port=53,
            transport_proto="UDP",
            app_proto="DNS",
            payload=b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
        ),
        PacketRecord(
            packet_number=2,
            timestamp=1700000000.05,
            wire_length=120,
            src_ip="10.0.0.99",
            dst_ip="192.168.1.200",
            src_port=4444,
            dst_port=50123,
            transport_proto="TCP",
            payload=b"whoami; /bin/sh -i; password=admin123",
        ),
    ]


def test_build_analysis_payload(sample_records: list[PacketRecord]):
    payload = build_analysis_payload(sample_records, "test.pcap")
    assert "metadata" in payload
    assert "executive_summary" in payload
    assert "harvested_iocs" in payload
    assert "suspicious_packets" in payload
    assert payload["metadata"]["total_packets"] == 2
    assert len(payload["suspicious_packets"]) >= 1
    assert payload["executive_summary"]["highest_risk_score"] >= 80


def test_export_json(tmp_path: Path, sample_records: list[PacketRecord]):
    payload = build_analysis_payload(sample_records, "test.pcap")
    json_path = tmp_path / "output.json"
    out = export_json(payload, json_path)
    assert out.exists()

    with open(out, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["metadata"]["total_packets"] == 2


def test_generate_pdf_report(tmp_path: Path, sample_records: list[PacketRecord]):
    payload = build_analysis_payload(sample_records, "test.pcap")
    pdf_path = tmp_path / "report.pdf"
    out = generate_pdf_report(payload, pdf_path)
    assert out.exists()
    assert out.stat().st_size > 1000  # valid PDF generated
