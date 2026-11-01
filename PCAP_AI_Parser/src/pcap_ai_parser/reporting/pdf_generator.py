"""
pdf_generator.py — automated forensic PDF report builder using ReportLab.

Produces a publication-quality, multi-page Network Forensics & Threat Intelligence Report
matching academic and enterprise reporting standards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _get_severity_color(sev: str) -> colors.Color:
    mapping = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#d97706"),
        "LOW": colors.HexColor("#0284c7"),
        "CLEAN": colors.HexColor("#16a34a"),
    }
    return mapping.get(sev.upper(), colors.HexColor("#64748b"))


def generate_pdf_report(analysis_data: dict[str, Any], output_path: str | Path) -> Path:
    """
    Generate an executive PDF forensic report from analysis dictionary.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "TableBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )
    body_bold = ParagraphStyle(
        "TableBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    story = []

    # ── Header Banner ─────────────────────────────────────────────────────────
    story.append(Paragraph("PACKETPARSER-AI", title_style))
    story.append(
        Paragraph(
            "Automated PCAP Payload Intelligence & Threat Triage Forensic Report",
            subtitle_style,
        )
    )
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb"), spaceAfter=14))

    meta = analysis_data.get("metadata", {})
    exec_sum = analysis_data.get("executive_summary", {})
    sev_breakdown = exec_sum.get("severity_breakdown", {})

    # ── Executive Metadata Table ──────────────────────────────────────────────
    verdict = exec_sum.get("overall_verdict", "N/A")
    verdict_color = (
        "#dc2626" if "CRITICAL" in verdict
        else "#ea580c" if "HIGH" in verdict
        else "#d97706" if "SUSPICIOUS" in verdict
        else "#16a34a"
    )

    meta_table_data = [
        [
            Paragraph("Target File:", body_bold),
            Paragraph(Path(meta.get("source_file", "unknown")).name, body_style),
            Paragraph("Overall Verdict:", body_bold),
            Paragraph(f"<font color='{verdict_color}'><b>{verdict}</b></font>", body_style),
        ],
        [
            Paragraph("Analysis Time:", body_bold),
            Paragraph(meta.get("analyzed_at", "")[:19].replace("T", " ") + " UTC", body_style),
            Paragraph("Peak Risk Score:", body_bold),
            Paragraph(f"<b>{exec_sum.get('highest_risk_score', 0)} / 100</b>", body_style),
        ],
        [
            Paragraph("Total Packets:", body_bold),
            Paragraph(f"{meta.get('total_packets', 0):,}", body_style),
            Paragraph("Payload Packets:", body_bold),
            Paragraph(f"{meta.get('packets_with_payload', 0):,}", body_style),
        ],
    ]

    t_meta = Table(meta_table_data, colWidths=[80, 190, 95, 175])
    t_meta.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_meta)
    story.append(Spacer(1, 14))

    # ── Threat Posture Breakdown ──────────────────────────────────────────────
    story.append(Paragraph("Threat Severity Breakdown", h1_style))
    
    sev_rows = [
        [
            Paragraph("Severity Level", header_style),
            Paragraph("Packet Count", header_style),
            Paragraph("Percentage", header_style),
            Paragraph("Description", header_style),
        ],
        [
            Paragraph("<font color='#dc2626'><b>CRITICAL</b></font>", body_style),
            Paragraph(str(sev_breakdown.get("CRITICAL", 0)), body_style),
            Paragraph(f"{(sev_breakdown.get('CRITICAL', 0) / max(1, meta.get('total_packets', 1))) * 100:.1f}%", body_style),
            Paragraph("Active exploits, remote shells, confirmed attack signatures", body_style),
        ],
        [
            Paragraph("<font color='#ea580c'><b>HIGH</b></font>", body_style),
            Paragraph(str(sev_breakdown.get("HIGH", 0)), body_style),
            Paragraph(f"{(sev_breakdown.get('HIGH', 0) / max(1, meta.get('total_packets', 1))) * 100:.1f}%", body_style),
            Paragraph("High-entropy packed payloads on non-standard ports", body_style),
        ],
        [
            Paragraph("<font color='#d97706'><b>MEDIUM</b></font>", body_style),
            Paragraph(str(sev_breakdown.get("MEDIUM", 0)), body_style),
            Paragraph(f"{(sev_breakdown.get('MEDIUM', 0) / max(1, meta.get('total_packets', 1))) * 100:.1f}%", body_style),
            Paragraph("Cleartext credentials, web probe injections, obfuscated IOCs", body_style),
        ],
        [
            Paragraph("<font color='#0284c7'><b>LOW</b></font>", body_style),
            Paragraph(str(sev_breakdown.get("LOW", 0)), body_style),
            Paragraph(f"{(sev_breakdown.get('LOW', 0) / max(1, meta.get('total_packets', 1))) * 100:.1f}%", body_style),
            Paragraph("Unencrypted legacy protocols (FTP, Telnet control channel)", body_style),
        ],
        [
            Paragraph("<font color='#16a34a'><b>CLEAN</b></font>", body_style),
            Paragraph(str(sev_breakdown.get("CLEAN", 0)), body_style),
            Paragraph(f"{(sev_breakdown.get('CLEAN', 0) / max(1, meta.get('total_packets', 1))) * 100:.1f}%", body_style),
            Paragraph("Standard baseline network traffic without threat indicators", body_style),
        ],
    ]

    t_sev = Table(sev_rows, colWidths=[85, 80, 75, 300])
    t_sev.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(t_sev)
    story.append(Spacer(1, 14))

    # ── Harvested IOCs Table ──────────────────────────────────────────────────
    iocs = analysis_data.get("harvested_iocs", [])
    if iocs:
        story.append(Paragraph(f"Harvested Indicators of Compromise ({len(iocs)} Unique)", h1_style))
        ioc_table_data = [
            [
                Paragraph("Type", header_style),
                Paragraph("Indicator / Value", header_style),
                Paragraph("Hits", header_style),
                Paragraph("Packet References", header_style),
            ]
        ]
        for item in iocs[:25]:  # top 25 IOCs
            pkts = ", ".join(f"#{p}" for p in item["packet_references"][:5])
            if len(item["packet_references"]) > 5:
                pkts += f" (+{len(item['packet_references'])-5} more)"
            ioc_table_data.append([
                Paragraph(f"<b>{item['type']}</b>", body_style),
                Paragraph(item["value"], body_style),
                Paragraph(str(item["frequency"]), body_style),
                Paragraph(pkts, body_style),
            ])

        t_ioc = Table(ioc_table_data, colWidths=[70, 270, 45, 155])
        t_ioc.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_ioc)
        story.append(Spacer(1, 14))

    # ── Top Flagged Suspicious Packets ────────────────────────────────────────
    suspicious = analysis_data.get("suspicious_packets", [])
    if suspicious:
        story.append(Paragraph(f"Flagged Suspicious Packets (Top {min(15, len(suspicious))})", h1_style))
        susp_table_data = [
            [
                Paragraph("Pkt #", header_style),
                Paragraph("Proto", header_style),
                Paragraph("Flow", header_style),
                Paragraph("Score", header_style),
                Paragraph("Severity", header_style),
                Paragraph("Primary Forensic Findings", header_style),
            ]
        ]
        for pkt in suspicious[:15]:
            findings_txt = "<br/>".join(f"• {f}" for f in pkt.get("findings", [])[:2])
            sev_col = _get_severity_color(pkt.get("severity", "CLEAN")).hexval()
            susp_table_data.append([
                Paragraph(f"#{pkt['packet_number']}", body_bold),
                Paragraph(pkt["protocol"], body_style),
                Paragraph(f"{pkt['src']}<br/>&rarr; {pkt['dst']}", body_style),
                Paragraph(f"<b>{pkt['risk_score']}</b>", body_style),
                Paragraph(f"<font color='#{sev_col}'><b>{pkt['severity']}</b></font>", body_style),
                Paragraph(findings_txt, body_style),
            ])

        t_susp = Table(susp_table_data, colWidths=[40, 45, 145, 45, 60, 205])
        t_susp.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_susp)

    doc.build(story)
    return out_file
