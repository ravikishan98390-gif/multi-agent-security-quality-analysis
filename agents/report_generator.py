"""
report_generator.py — Generate PDF and JSON reports from job findings.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(job_id: str, submission_info: dict, summary: dict, findings: list[dict]) -> bytes:
    """Return a UTF-8-encoded JSON report as bytes."""
    report = {
        "report_type": "AI Code Review & Security Analysis",
        "job_id": job_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "file": submission_info.get("filename", "untitled"),
        "language": submission_info.get("language", "unknown"),
        "health_score": summary.get("health_score", 0),
        "summary": summary.get("summary", ""),
        "severity_counts": summary.get("counts", {}),
        "findings": [
            {
                "id": f["id"],
                "severity": f["severity"],
                "agent": f["source_agent"],
                "title": f["title"],
                "description": f["description"],
                "file": submission_info.get("filename", "untitled"),
                "line": f["line_start"],
                "line_end": f["line_end"],
                "category": f["category"],
                "fix": f.get("fix", ""),
            }
            for f in findings
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF report
# ---------------------------------------------------------------------------

def generate_pdf_report(job_id: str, submission_info: dict, summary: dict, findings: list[dict]) -> bytes:
    """Return a PDF report as bytes using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        import io

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "ReportTitle", parent=styles["Title"],
            fontSize=20, textColor=colors.HexColor("#6366F1"), spaceAfter=6
        )
        h2_style = ParagraphStyle(
            "H2", parent=styles["Heading2"],
            fontSize=13, textColor=colors.HexColor("#374151"), spaceAfter=4
        )
        body_style = styles["BodyText"]
        body_style.fontSize = 9

        SEVERITY_COLORS = {
            "critical": colors.HexColor("#F43F5E"),
            "high": colors.HexColor("#F97316"),
            "medium": colors.HexColor("#EAB308"),
            "low": colors.HexColor("#3B82F6"),
        }

        story = []

        # Header
        story.append(Paragraph("AI Code Review & Security Analysis", title_style))
        story.append(Paragraph(
            f"Job: {job_id[:8]}... | File: {submission_info.get('filename','untitled')} | "
            f"Language: {submission_info.get('language','?').title()} | "
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            body_style
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.4*cm))

        # Score & Summary
        score = summary.get("health_score", 0)
        score_color = (
            colors.HexColor("#10B981") if score >= 80
            else colors.HexColor("#F59E0B") if score >= 50
            else colors.HexColor("#EF4444")
        )
        story.append(Paragraph(f"Health Score: {score}/100", h2_style))
        story.append(Paragraph(summary.get("summary", ""), body_style))
        story.append(Spacer(1, 0.3*cm))

        # Severity breakdown table
        counts = summary.get("counts", {})
        sev_data = [["Severity", "Count"]]
        for sev in ("critical", "high", "medium", "low"):
            sev_data.append([sev.capitalize(), str(counts.get(sev, 0))])
        sev_table = Table(sev_data, colWidths=[4*cm, 2*cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366F1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.5*cm))

        # Findings
        story.append(Paragraph("Findings", h2_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))

        for f in findings:
            sev = f["severity"]
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)
            story.append(Spacer(1, 0.2*cm))

            # Finding header row
            hdr_data = [[
                Paragraph(f"<b>{sev.upper()}</b>", body_style),
                Paragraph(f"<b>{f['title']}</b>", body_style),
                Paragraph(f"L{f['line_start']}", body_style),
                Paragraph(f.get("source_agent", ""), body_style),
            ]]
            hdr_table = Table(hdr_data, colWidths=[2.2*cm, 10*cm, 1.5*cm, 3*cm])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), sev_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(hdr_table)

            # Description
            story.append(Paragraph(f["description"], body_style))
            if f.get("fix"):
                story.append(Paragraph(
                    f"<b>Fix:</b> {f['fix']}", body_style
                ))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        # Fallback: return JSON if reportlab not installed
        return generate_json_report(job_id, submission_info, summary, findings)
