"""PDF generation via WeasyPrint (Python package or system CLI) with ReportLab fallback."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from reporting.html_report import render_html
from reporting.schema import ReportResult


def weasyprint_available() -> bool:
    """True if a WeasyPrint backend can produce PDFs."""
    try:
        import weasyprint  # noqa: F401

        return True
    except Exception:
        return shutil.which("weasyprint") is not None


def reportlab_available() -> bool:
    try:
        import reportlab  # noqa: F401

        return True
    except Exception:
        return False


def pdf_backend_available() -> bool:
    return weasyprint_available() or reportlab_available()


def _write_pdf_weasyprint_module(html: str, path: Path) -> None:
    from weasyprint import HTML

    HTML(string=html).write_pdf(str(path))


def _write_pdf_weasyprint_cli(html: str, path: Path) -> None:
    binary = shutil.which("weasyprint")
    if not binary:
        raise RuntimeError("weasyprint CLI not found")
    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp) / "report.html"
        html_path.write_text(html, encoding="utf-8")
        proc = subprocess.run(
            [binary, str(html_path), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not path.exists() or path.stat().st_size == 0:
            detail = (proc.stderr or proc.stdout or "unknown error").strip()
            raise RuntimeError(f"weasyprint CLI failed: {detail[:400]}")


def _write_pdf_reportlab(result: ReportResult, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    meta = result.metadata
    summary = result.summary
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "VSTitle",
        parent=styles["Heading1"],
        textColor=colors.HexColor("#0f4c5c"),
        fontSize=16,
        spaceAfter=8,
    )
    h2 = ParagraphStyle(
        "VSH2",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0f4c5c"),
        fontSize=12,
        spaceBefore=10,
        spaceAfter=6,
    )
    body = ParagraphStyle("VSBody", parent=styles["Normal"], fontSize=9, leading=12)

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    story = []
    story.append(Paragraph(meta.get("report_title", "VulnSight Report"), title_style))
    story.append(
        Paragraph(
            f"Target: {meta.get('target', '')}<br/>"
            f"Generated (UTC): {meta.get('generated_at', '')}<br/>"
            f"Scanner: {meta.get('scanner_version', '')} · "
            f"Scan ID: {meta.get('scan_id', '')}",
            body,
        )
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph("Executive summary", h2))
    story.append(
        Paragraph(
            f"Unique findings: <b>{summary.get('total_unique_findings', 0)}</b> · "
            f"Highest CVSS: <b>{summary.get('highest_cvss_score') if summary.get('highest_cvss_score') is not None else '—'}</b>",
            body,
        )
    )
    story.append(Paragraph("Findings", h2))

    if not result.findings:
        story.append(Paragraph("No findings to display.", body))
    else:
        data = [["Title", "Sev", "CVSS", "Status", "Module"]]
        for f in result.findings[:80]:
            cvss = (
                f"{f.cvss_base_score:.1f}"
                if f.cvss_base_score is not None
                else "—"
            )
            data.append(
                [
                    Paragraph((f.title or "")[:90], body),
                    f.severity,
                    cvss,
                    f.verification_status,
                    f.source_module,
                ]
            )
        table = Table(data, colWidths=[70 * mm, 18 * mm, 14 * mm, 22 * mm, 28 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f4c5c")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e2e0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f7f6")]),
                ]
            )
        )
        story.append(table)

        for idx, f in enumerate(result.findings[:40], start=1):
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"{idx}. {f.title}", h2))
            story.append(
                Paragraph(
                    f"<b>Endpoint:</b> {f.method} {f.url}<br/>"
                    f"<b>Severity:</b> {f.severity} · <b>Verification:</b> {f.verification_status}<br/>"
                    f"<b>Description:</b> {(f.description or '')[:500]}<br/>"
                    f"<b>Remediation:</b> {(f.remediation or '')[:500]}",
                    body,
                )
            )

    doc.build(story)


def write_pdf(result: ReportResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result)
    errors: list[str] = []

    # Prefer WeasyPrint Python package
    try:
        import weasyprint  # noqa: F401

        _write_pdf_weasyprint_module(html, path)
        if path.exists() and path.stat().st_size > 0:
            return path
    except Exception as exc:  # noqa: BLE001
        errors.append(f"weasyprint-module: {exc}")

    # System weasyprint CLI
    if shutil.which("weasyprint"):
        try:
            _write_pdf_weasyprint_cli(html, path)
            if path.exists() and path.stat().st_size > 0:
                return path
        except Exception as exc:  # noqa: BLE001
            errors.append(f"weasyprint-cli: {exc}")

    # ReportLab text/table fallback
    if reportlab_available():
        try:
            _write_pdf_reportlab(result, path)
            if path.exists() and path.stat().st_size > 0:
                return path
        except Exception as exc:  # noqa: BLE001
            errors.append(f"reportlab: {exc}")

    detail = "; ".join(errors) if errors else "no PDF backend available"
    raise RuntimeError(
        "PDF generation failed. Install weasyprint (pip install 'vulnsight[pdf]' "
        f"or system weasyprint) or reportlab. Details: {detail}"
    )
