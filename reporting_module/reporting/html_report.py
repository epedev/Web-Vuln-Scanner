"""Self-contained HTML report generation with autoescaping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reporting.schema import CanonicalFinding, ReportResult

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def render_html(result: ReportResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(
        metadata=result.metadata,
        summary=result.summary,
        findings=[_view(f) for f in result.findings],
        limitations=result.limitations,
        modules_executed=result.modules_executed,
        modules_not_executed=result.modules_not_executed,
        incomplete=result.incomplete,
        issues=[i.to_dict() for i in result.issues],
    )


def write_html(result: ReportResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result)
    path.write_text(html, encoding="utf-8")
    if not path.exists() or path.stat().st_size == 0:
        raise OSError(f"HTML report was not written: {path}")
    return path


def _view(f: CanonicalFinding) -> dict[str, Any]:
    return f.to_dict()
