"""Markdown report writer for VulnSight assessments."""

from __future__ import annotations

from pathlib import Path

from reporting.schema import ReportResult


def _md_escape(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(result: ReportResult) -> str:
    """Render a self-contained Markdown assessment report."""
    meta = result.metadata
    summary = result.summary
    lines: list[str] = []

    lines.append(f"# {meta.get('report_title', 'Web Vulnerability Assessment Report')}")
    lines.append("")
    lines.append(f"**{meta.get('product', 'VulnSight')}**")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Target | `{_md_escape(str(meta.get('target', '')))}` |")
    lines.append(f"| Authorized origin | `{_md_escape(str(meta.get('authorized_origin', '')))}` |")
    lines.append(f"| Assessment date | {meta.get('assessment_date', '')} |")
    lines.append(f"| Generated (UTC) | {meta.get('generated_at', '')} |")
    lines.append(f"| Scan ID | `{meta.get('scan_id', '')}` |")
    lines.append(f"| Scanner version | {meta.get('scanner_version', '')} |")
    lines.append("")

    if result.incomplete:
        lines.append(
            "> **Incomplete assessment:** one or more inputs failed validation "
            "or listed modules were not executed."
        )
        lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append(f"- **Unique findings:** {summary.get('total_unique_findings', 0)}")
    highest = summary.get("highest_cvss_score")
    lines.append(
        f"- **Highest CVSS:** {highest if highest is not None else '—'}"
    )
    by_ver = summary.get("by_verification_status") or {}
    lines.append(f"- **Confirmed:** {by_ver.get('confirmed', 0)}")
    lines.append(f"- **Probable:** {by_ver.get('probable', 0)}")
    lines.append(f"- **Candidates:** {by_ver.get('candidate', 0)}")
    lines.append(f"- **Unscored:** {summary.get('unscored_findings', 0)}")
    lines.append("")

    lines.append("### Severity counts")
    lines.append("")
    by_sev = summary.get("by_severity") or {}
    if by_sev:
        for sev, count in by_sev.items():
            lines.append(f"- {sev}: {count}")
    else:
        lines.append("- No findings.")
    lines.append("")

    lines.append("### By source module")
    lines.append("")
    for mod, count in (summary.get("by_source_module") or {}).items():
        lines.append(f"- {mod}: {count}")
    lines.append("")

    lines.append("### Major observations")
    lines.append("")
    observations = summary.get("major_observations") or []
    if observations:
        for obs in observations:
            lines.append(f"- {_md_escape(str(obs))}")
    else:
        lines.append("- No major observations.")
    lines.append("")

    owasp = summary.get("owasp_top10") or {}
    if owasp:
        lines.append("## OWASP Top 10:2025 coverage")
        lines.append("")
        std = owasp.get("standard", "OWASP Top 10:2025")
        window = owasp.get("edition_window")
        lines.append(
            f"**Standard:** {std}"
            + (f" ({window} cycle)" if window else "")
        )
        lines.append("")
        lines.append(
            f"Categories with findings: "
            f"**{owasp.get('categories_with_findings', 0)}** / "
            f"{owasp.get('categories_tracked', 10)}"
        )
        lines.append("")
        if owasp.get("note"):
            lines.append(f"> {_md_escape(str(owasp['note']))}")
            lines.append("")
        lines.append("| ID | Category | Findings | Status | VulnSight coverage |")
        lines.append("| --- | --- | --- | --- | --- |")
        for row in owasp.get("categories") or []:
            lines.append(
                "| "
                + " | ".join(
                    [
                        row.get("id", ""),
                        _md_escape(str(row.get("name", ""))),
                        str(row.get("findings", 0)),
                        str(row.get("status", "")).replace("_", " "),
                        _md_escape(str(row.get("vulnsight_coverage", ""))),
                    ]
                )
                + " |"
            )
        lines.append("")
        legacy = owasp.get("legacy_2021") or {}
        if legacy.get("categories"):
            lines.append("### Legacy OWASP Top 10:2021 continuity")
            lines.append("")
            if legacy.get("note"):
                lines.append(f"> {_md_escape(str(legacy['note']))}")
                lines.append("")
            lines.append("| ID | Category | Findings | Status |")
            lines.append("| --- | --- | --- | --- |")
            for row in legacy.get("categories") or []:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            row.get("id", ""),
                            _md_escape(str(row.get("name", ""))),
                            str(row.get("findings", 0)),
                            str(row.get("status", "")).replace("_", " "),
                        ]
                    )
                    + " |"
                )
            lines.append("")

    lines.append("## Findings overview")
    lines.append("")
    if result.findings:
        lines.append(
            "| ID | Title | Severity | CVSS | Verification | URL | Param | CWE | Module |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for f in result.findings:
            cvss = (
                f"{f.cvss_base_score:.1f}"
                if f.cvss_base_score is not None
                else "—"
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        f.id[:8],
                        _md_escape(f.title),
                        f.severity,
                        cvss,
                        f.verification_status,
                        f"`{_md_escape(f.url)}`",
                        _md_escape(f.parameter or "—"),
                        f.cwe or "—",
                        f.source_module,
                    ]
                )
                + " |"
            )
    else:
        lines.append("_No findings to display._")
    lines.append("")

    lines.append("## Detailed findings")
    lines.append("")
    if not result.findings:
        lines.append("_No detailed findings._")
        lines.append("")
    for idx, f in enumerate(result.findings, start=1):
        lines.append(f"### {idx}. {_md_escape(f.title)}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity}")
        if f.cvss_base_score is not None:
            lines.append(
                f"- **CVSS:** {f.cvss_version or '3.1'} {f.cvss_base_score:.1f}"
                f" ({f.cvss_severity or 'n/a'})"
            )
            if f.cvss_vector:
                lines.append(f"- **CVSS vector:** `{f.cvss_vector}`")
        else:
            lines.append(f"- **CVSS:** unscored ({f.cvss_status})")
        lines.append(f"- **Verification:** {f.verification_status}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Priority:** {f.operational_priority or 'n/a'}")
        lines.append(f"- **Endpoint:** `{f.method} {_md_escape(f.url)}`")
        if f.parameter:
            lines.append(f"- **Parameter:** `{_md_escape(f.parameter)}`")
        lines.append(f"- **Description:** {_md_escape(f.description)}")
        lines.append(f"- **Impact:** {_md_escape(f.impact)}")
        lines.append(f"- **Remediation:** {_md_escape(f.remediation)}")
        lines.append(
            f"- **Classification:** {f.cwe or 'n/a'} · {f.owasp or 'n/a'}"
        )
        lines.append(f"- **Source module:** {f.source_module}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated by VulnSight · timestamps in UTC · treat all evidence as untrusted data._"
    )
    lines.append("")
    lines.append(
        f"_Modules executed: {', '.join(result.modules_executed) or 'none'}. "
        f"Schema {meta.get('schema_version', '1.0')}._"
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown(result: ReportResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(result), encoding="utf-8")
    if not path.exists() or path.stat().st_size == 0:
        raise OSError(f"Markdown report was not written: {path}")
    return path
