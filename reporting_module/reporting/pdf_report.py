"""Optional PDF generation via WeasyPrint HTML-to-PDF."""

from __future__ import annotations

from pathlib import Path

from reporting.html_report import render_html
from reporting.schema import ReportResult


def weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401

        return True
    except Exception:
        return False


def write_pdf(result: ReportResult, path: str | Path) -> Path:
    path = Path(path)
    if not weasyprint_available():
        raise RuntimeError(
            "PDF generation requires weasyprint. Install optional dependency "
            "or omit --pdf."
        )
    from weasyprint import HTML

    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result)
    HTML(string=html).write_pdf(str(path))
    if not path.exists() or path.stat().st_size == 0:
        raise OSError(f"PDF report was not written: {path}")
    return path
