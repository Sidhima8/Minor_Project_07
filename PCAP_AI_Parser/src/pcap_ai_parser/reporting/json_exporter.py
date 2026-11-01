"""
json_exporter.py — structured JSON report generator for PCAP forensics.

Compiles comprehensive packet metrics, harvested IOCs, byte-level decodings,
and threat intelligence findings into an exportable JSON schema.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pcap_ai_parser.analyzer import PayloadDecoder, normalize_payload
from pcap_ai_parser.intelligence import HeuristicRiskScorer
from pcap_ai_parser.models.packet import PacketRecord


def build_analysis_payload(
    records: list[PacketRecord],
    source_file: str,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run full pipeline (normalization, decoding, IOCs, risk scoring) over records
    and assemble an exhaustive analysis dictionary.
    """
    scorer = HeuristicRiskScorer()
    decoder = PayloadDecoder()

    severity_counts = {"CLEAN": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    suspicious_packets = []
    aggregated_iocs: dict[tuple[str, str], list[int]] = {}
    detailed_packets = []

    total_bytes = 0
    payload_count = 0
    max_risk_score = 0

    for rec in records:
        total_bytes += rec.wire_length
        has_payload = bool(rec.payload)
        if has_payload:
            payload_count += 1

        # Decoders
        artifacts = decoder.decode_all(rec.payload) if has_payload else []
        decoded_texts = [a.decoded_text for a in artifacts]

        # Threat Assessment
        assessment = scorer.evaluate(rec, decoded_texts=decoded_texts)
        severity_counts[assessment.severity] = severity_counts.get(assessment.severity, 0) + 1
        if assessment.score > max_risk_score:
            max_risk_score = assessment.score

        # IOC aggregation
        for ioc in assessment.iocs:
            key = (ioc.ioc_type, ioc.value)
            if key not in aggregated_iocs:
                aggregated_iocs[key] = []
            if rec.packet_number not in aggregated_iocs[key]:
                aggregated_iocs[key].append(rec.packet_number)

        pkt_summary = {
            "packet_number": rec.packet_number,
            "timestamp": rec.timestamp,
            "protocol": rec.transport_proto or rec.network_proto,
            "app_proto": rec.app_proto or "Unknown",
            "src": f"{rec.src_ip}:{rec.src_port}" if rec.src_port else rec.src_ip,
            "dst": f"{rec.dst_ip}:{rec.dst_port}" if rec.dst_port else rec.dst_ip,
            "wire_length": rec.wire_length,
            "payload_length": rec.payload_length,
            "risk_score": assessment.score,
            "severity": assessment.severity,
            "findings": assessment.findings,
            "entropy": assessment.entropy,
            "iocs": [ioc.to_dict() for ioc in assessment.iocs],
            "decoded_artifacts": [a.to_dict() for a in artifacts],
        }

        detailed_packets.append(pkt_summary)

        if assessment.score >= 1:
            suspicious_packets.append(pkt_summary)

    # Format IOCs for export
    iocs_list = [
        {"type": ioc_type, "value": val, "packet_references": pkts, "frequency": len(pkts)}
        for (ioc_type, val), pkts in aggregated_iocs.items()
    ]
    iocs_list.sort(key=lambda x: (x["type"], -x["frequency"]))

    # Sort suspicious packets descending by risk
    suspicious_packets.sort(key=lambda x: (-x["risk_score"], x["packet_number"]))

    # Overall system threat posture
    if severity_counts["CRITICAL"] > 0:
        overall_verdict = "CRITICAL THREATS DETECTED"
    elif severity_counts["HIGH"] > 0:
        overall_verdict = "HIGH RISK TRAFFIC IDENTIFIED"
    elif severity_counts["MEDIUM"] > 0:
        overall_verdict = "SUSPICIOUS ACTIVITY FLAGGED"
    elif severity_counts["LOW"] > 0:
        overall_verdict = "INFORMATIONAL ANOMALIES"
    else:
        overall_verdict = "CLEAN / BENIGN"

    return {
        "metadata": {
            "system": "PacketParser-AI",
            "version": "0.1.0",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "source_file": str(source_file),
            "total_packets": len(records),
            "total_bytes": total_bytes,
            "packets_with_payload": payload_count,
        },
        "executive_summary": {
            "overall_verdict": overall_verdict,
            "highest_risk_score": max_risk_score,
            "severity_breakdown": severity_counts,
            "total_suspicious_packets": len(suspicious_packets),
            "unique_iocs_found": len(iocs_list),
        },
        "statistics": stats or {},
        "harvested_iocs": iocs_list,
        "suspicious_packets": suspicious_packets,
        "packets": detailed_packets,
    }


def export_json(data: dict[str, Any], output_path: str | Path) -> Path:
    """Save analysis payload to a JSON file on disk."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return out
