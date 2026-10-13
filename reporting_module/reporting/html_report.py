"""Self-contained HTML report generation with autoescaping."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reporting.markdown_report import render_markdown
from reporting.schema import CanonicalFinding, ReportResult

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def render_html(
    result: ReportResult,
    *,
    artifact_links: dict[str, Any] | None = None,
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    template = env.get_template("report.html.j2")
    links: dict[str, Any] = {
        "md": "vulnsight_report.md",
        "pdf": "vulnsight_report.pdf",
        "json": "normalized_findings.json",
        "pdf_available": True,
    }
    if artifact_links:
        links.update(artifact_links)
    return template.render(
        metadata=result.metadata,
        summary=result.summary,
        findings=[_view(f) for f in result.findings],
        limitations=result.limitations,
        modules_executed=result.modules_executed,
        modules_not_executed=result.modules_not_executed,
        incomplete=result.incomplete,
        issues=[i.to_dict() for i in result.issues],
        artifact_links=links,
        markdown_source=render_markdown(result),
    )


def write_html(
    result: ReportResult,
    path: str | Path,
    *,
    artifact_links: dict[str, Any] | None = None,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html(result, artifact_links=artifact_links)
    path.write_text(html, encoding="utf-8")
    if not path.exists() or path.stat().st_size == 0:
        raise OSError(f"HTML report was not written: {path}")
    return path


def _view(f: CanonicalFinding) -> dict[str, Any]:
    data = f.to_dict()
    data["source_files"] = [str(x) for x in (f.source_files or []) if x is not None]
    data["source_ids"] = [str(x) for x in (f.source_ids or []) if x is not None]
    return data
