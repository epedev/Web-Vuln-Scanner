"""Reporting pipeline orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from reporting.deduplication import deduplicate
from reporting.html_report import write_html
from reporting.ingestion import load_json_file, load_json_object
from reporting.normalization import normalize_bundle
from reporting.markdown_report import write_markdown
from reporting.pdf_report import pdf_backend_available, write_pdf
from reporting.risk import apply_operational_priority, build_summary, sort_findings
from reporting.schema import (
    SCHEMA_VERSION,
    CanonicalFinding,
    ReportResult,
    ValidationIssue,
    utc_now_iso,
)

PRODUCT_NAME = "VulnSight — Intelligent Web Vulnerability Scanner"
KNOWN_MODULES = (
    "recon",
    "xss",
    "sqli",
    "command_injection",
    "access_control",
    "misconfig",
    "reporting",
)


def run_report_pipeline(
    *,
    input_paths: list[str] | None = None,
    findings_objects: list[dict[str, Any]] | None = None,
    module_hints: dict[str, str] | None = None,
    target: str = "unspecified",
    authorized_origin: str = "unspecified",
    scope: str = "Authorized lab assessment scope as configured by the operator.",
    assessment_date: str | None = None,
    scan_id: str | None = None,
    scanner_version: str = "0.1.0",
    apply_cvss_suggestions: bool = True,
    strict: bool = False,
    modules_executed: list[str] | None = None,
    modules_not_executed: list[str] | None = None,
    extra_limitations: list[str] | None = None,
) -> ReportResult:
    """Ingest, normalize, score, dedupe, and summarize findings."""
    issues: list[ValidationIssue] = []
    all_findings: list[CanonicalFinding] = []
    limitations: list[str] = list(extra_limitations or [])
    incomplete = False
    hints = module_hints or {}

    for path in input_paths or []:
        hint = hints.get(path)
        bundle = load_json_file(path)
        if hint:
            bundle.source_module_hint = hint
        if not bundle.ok:
            incomplete = True
            issues.extend(bundle.issues)
            if strict:
                break
            continue
        issues.extend([i for i in bundle.issues if i not in issues])
        limitations.extend(bundle.limitations)
        findings, norm_issues = normalize_bundle(
            bundle, apply_cvss_suggestions=apply_cvss_suggestions
        )
        issues.extend(norm_issues)
        if strict and any(i.level == "error" for i in norm_issues):
            incomplete = True
            break
        all_findings.extend(findings)

    for idx, obj in enumerate(findings_objects or []):
        hint = hints.get(f"object:{idx}")
        bundle = load_json_object(
            obj, source_path=f"<object:{idx}>", source_module_hint=hint
        )
        if not bundle.ok:
            incomplete = True
            issues.extend(bundle.issues)
            if strict:
                break
            continue
        findings, norm_issues = normalize_bundle(
            bundle, apply_cvss_suggestions=apply_cvss_suggestions
        )
        issues.extend(norm_issues)
        all_findings.extend(findings)

    if strict and any(i.level == "error" for i in issues):
        incomplete = True

    deduped = deduplicate(all_findings)
    apply_operational_priority(deduped)
    ordered = sort_findings(deduped)
    summary = build_summary(ordered)

    executed = modules_executed or sorted(
        {f.source_module for f in ordered if f.source_module}
    )
    not_executed = modules_not_executed
    if not_executed is None:
        not_executed = [m for m in KNOWN_MODULES if m not in executed]

    if not_executed:
        limitations.append(
            "Modules not executed (do not interpret as zero findings): "
            + ", ".join(not_executed)
        )
    limitations.append(
        "CVSS vectors marked analyst_assessed are provisional metric selections "
        "based on vulnerability class and evidence quality, not lab-measured values."
    )
    limitations.append("Timestamps are recorded in UTC (ISO-8601).")

    metadata = {
        "product": PRODUCT_NAME,
        "report_title": "Web Vulnerability Assessment Report",
        "target": target,
        "authorized_origin": authorized_origin,
        "scope": scope,
        "assessment_date": assessment_date or utc_now_iso()[:10],
        "generated_at": utc_now_iso(),
        "scan_id": scan_id or str(uuid4()),
        "scanner_version": scanner_version,
        "schema_version": SCHEMA_VERSION,
        "purpose": (
            "Security assessment report for authorized testing / academic review. "
            "Not a penetration-test certification."
        ),
    }

    return ReportResult(
        findings=ordered,
        issues=issues,
        summary=summary,
        metadata=metadata,
        limitations=limitations,
        modules_executed=list(executed),
        modules_not_executed=list(not_executed),
        incomplete=incomplete,
    )


def generate_report(
    *,
    output_dir: str | Path,
    input_paths: list[str] | None = None,
    findings_objects: list[dict[str, Any]] | None = None,
    formats: list[str] | None = None,
    write_json: bool = True,
    module_hints: dict[str, str] | None = None,
    pdf: bool = False,
    **pipeline_kwargs: Any,
) -> ReportResult:
    """Run pipeline and write HTML / JSON / Markdown / PDF artifacts."""
    formats = formats or ["html"]
    result = run_report_pipeline(
        input_paths=input_paths,
        findings_objects=findings_objects,
        module_hints=module_hints,
        **pipeline_kwargs,
    )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {}

    if write_json or "json" in formats:
        json_path = out / "normalized_findings.json"
        json_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if json_path.stat().st_size == 0:
            raise OSError("normalized JSON was empty")
        outputs["json"] = str(json_path)

    # Write downloadable artifacts before HTML so sibling links resolve.
    if "md" in formats or "markdown" in formats:
        md_path = write_markdown(result, out / "vulnsight_report.md")
        outputs["md"] = str(md_path)

    pdf_available = False
    if pdf or "pdf" in formats:
        if not pdf_backend_available():
            result.limitations.append(
                "PDF requested but no PDF backend is available "
                "(install weasyprint or reportlab). HTML/JSON/Markdown still written."
            )
        else:
            try:
                pdf_path = write_pdf(result, out / "vulnsight_report.pdf")
                outputs["pdf"] = str(pdf_path)
                pdf_available = True
            except Exception as exc:  # noqa: BLE001
                result.limitations.append(f"PDF generation failed: {exc}")

    if "html" in formats:
        artifact_links = {
            "md": "vulnsight_report.md",
            "pdf": "vulnsight_report.pdf",
            "json": "normalized_findings.json",
            "pdf_available": bool(
                pdf_available or (out / "vulnsight_report.pdf").exists()
            ),
        }
        html_path = write_html(
            result, out / "vulnsight_report.html", artifact_links=artifact_links
        )
        outputs["html"] = str(html_path)

    result.outputs = outputs
    return result
