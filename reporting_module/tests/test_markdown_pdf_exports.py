
from pathlib import Path

from reporting.engine import generate_report
from reporting.markdown_report import render_markdown, write_markdown
from reporting.pdf_report import pdf_backend_available, write_pdf


def _sample_objects():
    return [
        {
            "title": "Test XSS finding",
            "vulnerability_type": "Cross-Site Scripting",
            "type": "xss",
            "url": "http://127.0.0.1:5001/reflect",
            "method": "GET",
            "parameter": "q",
            "severity": "medium",
            "confidence": "high",
            "verification_status": "candidate",
            "description": "Marker reflected.",
            "impact": "Script execution risk.",
            "remediation": "Encode output.",
            "cwe": "CWE-79",
            "module": "xss",
            "evidence": {"marker": "abc"},
        }
    ]


def test_markdown_report_written(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "json", "md"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
        modules_executed=["xss", "reporting"],
        modules_not_executed=[],
    )
    assert "md" in result.outputs
    md = Path(result.outputs["md"])
    text = md.read_text(encoding="utf-8")
    assert "Executive summary" in text
    assert "Test XSS finding" in text
    assert "# " in text


def test_html_contains_download_controls(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "md"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    html = Path(result.outputs["html"]).read_text(encoding="utf-8")
    assert "Download" in html
    assert "vulnsight_report.md" in html
    assert "vulnsight_report.pdf" in html
    assert "dl-md-inline" in html
    assert "dl-md-file" in html
    assert "dl-pdf" in html
    assert 'id="methodology"' not in html
    assert "Methodology and limitations" not in html
    assert "#methodology" not in html
    md = Path(result.outputs["md"]).read_text(encoding="utf-8")
    assert "Methodology and limitations" not in md


def test_pdf_when_backend_available(tmp_path):
    if not pdf_backend_available():
        result = generate_report(
            output_dir=tmp_path,
            findings_objects=_sample_objects(),
            formats=["html", "pdf"],
            pdf=True,
        )
        assert "pdf" not in result.outputs
        assert any("PDF" in x for x in result.limitations)
        assert result.incomplete is False
        return
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "pdf"],
        pdf=True,
        target="http://127.0.0.1:5001",
    )
    assert "pdf" in result.outputs
    pdf = Path(result.outputs["pdf"])
    assert pdf.exists() and pdf.stat().st_size > 100
