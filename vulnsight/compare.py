
"""Compare a current findings report against a secure baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_findings(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.get("findings") or [])
    raise ValueError("input must be a findings list or object with findings[]")


def _key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(finding.get("vulnerability_type") or finding.get("type") or "").lower(),
        str(finding.get("title") or "").lower(),
        str(finding.get("url") or "").lower(),
        str(finding.get("parameter") or "").lower(),
    )


def compare_findings(
    current_path: str | Path,
    baseline_path: str | Path,
) -> dict[str, Any]:
    """Return findings present in current but absent from secure baseline."""
    current = _load_findings(current_path)
    baseline = _load_findings(baseline_path)
    base_keys = {_key(f) for f in baseline}
    regressions = [f for f in current if _key(f) not in base_keys]
    shared = [f for f in current if _key(f) in base_keys]
    return {
        "baseline_findings": len(baseline),
        "current_findings": len(current),
        "new_or_regressed": regressions,
        "already_in_baseline": shared,
        "summary": {
            "new_count": len(regressions),
            "shared_count": len(shared),
            "secure_control_clean": len(baseline) == 0,
            "interpretation": (
                "Current scan introduced findings not present in the secure baseline. "
                "Use this for vulnerable-vs-secure lab comparison in academic demos."
                if regressions
                else "No new findings versus baseline (good secure-control signal if baseline is empty/secure)."
            ),
        },
    }


def write_compare_report(result: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "compare_report.json"
    md_path = out / "compare_report.md"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# VulnSight secure-vs-vulnerable comparison",
        "",
        f"- Baseline findings: {result['baseline_findings']}",
        f"- Current findings: {result['current_findings']}",
        f"- New / regressed findings: {result['summary']['new_count']}",
        f"- Shared with baseline: {result['summary']['shared_count']}",
        "",
        result["summary"]["interpretation"],
        "",
        "## New findings versus baseline",
        "",
    ]
    regs = result["new_or_regressed"]
    if not regs:
        lines.append("_None._")
    else:
        lines.append("| Title | Severity | URL | Module |")
        lines.append("| --- | --- | --- | --- |")
        for f in regs:
            lines.append(
                f"| {f.get('title','')} | {f.get('severity','')} | "
                f"`{f.get('url','')}` | {f.get('source_module') or f.get('module','')} |"
            )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json": str(json_path), "md": str(md_path)}
