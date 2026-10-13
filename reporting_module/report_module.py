#!/usr/bin/env python3
"""VulnSight reporting & risk-scoring entry point.

CLI:
  python report_module.py --xss findings_xss.json --sqli findings_sqli.json \\
      --misconfig findings_misconfig.json --format html --output reports/

Programmatic:
  from report_module import run_report_module
  result = run_report_module(xss_path="...", output_dir="reports/")
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Allow running from reporting_module/ directory
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from reporting.engine import generate_report
from reporting.schema import ReportResult


def run_report_module(
    *,
    xss_path: str | None = None,
    sqli_path: str | None = None,
    misconfig_path: str | None = None,
    extra_paths: list[str] | None = None,
    findings_objects: list[dict[str, Any]] | None = None,
    output_dir: str = "reports",
    formats: list[str] | None = None,
    pdf: bool = False,
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
    mark_incomplete: bool = False,
) -> ReportResult:
    """Programmatic API for the main scanner / orchestration layer."""
    paths: list[str] = []
    hints: dict[str, str] = {}
    executed: list[str] = list(modules_executed or [])

    def _add(path: str | None, module: str) -> None:
        if not path:
            return
        paths.append(path)
        hints[path] = module
        if module not in executed:
            executed.append(module)

    _add(xss_path, "xss")
    _add(sqli_path, "sqli")
    _add(misconfig_path, "misconfig")
    for p in extra_paths or []:
        paths.append(p)

    from reporting.engine import KNOWN_MODULES

    known = set(KNOWN_MODULES)
    not_exec = modules_not_executed
    if not_exec is None:
        not_exec = sorted(known - set(executed))

    limitations = list(extra_limitations or [])
    if mark_incomplete:
        limitations.append(
            "One or more scanner modules failed or were skipped; treat coverage as partial."
        )

    result = generate_report(
        output_dir=output_dir,
        input_paths=paths or None,
        findings_objects=findings_objects,
        formats=formats or ["html", "json"],
        pdf=pdf,
        module_hints=hints,
        target=target,
        authorized_origin=authorized_origin,
        scope=scope,
        assessment_date=assessment_date,
        scan_id=scan_id,
        scanner_version=scanner_version,
        apply_cvss_suggestions=apply_cvss_suggestions,
        strict=strict,
        modules_executed=executed,
        modules_not_executed=not_exec,
        extra_limitations=limitations,
    )
    if mark_incomplete:
        result.incomplete = True
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "VulnSight reporting & risk-scoring engine. Aggregates module findings, "
            "scores CVSS v3.1, and writes HTML/JSON/Markdown/PDF."
        )
    )
    p.add_argument("--xss", help="XSS module findings JSON")
    p.add_argument("--sqli", help="SQLi module findings JSON")
    p.add_argument("--misconfig", help="Misconfiguration module findings JSON")
    p.add_argument(
        "--input",
        action="append",
        default=[],
        help="Additional findings JSON (repeatable)",
    )
    p.add_argument(
        "--format",
        action="append",
        choices=["html", "json", "pdf", "md", "markdown"],
        default=[],
        help="Output format (repeatable). Default: html+json",
    )
    p.add_argument("--pdf", action="store_true", help="Also write PDF (WeasyPrint or ReportLab)")
    p.add_argument("--md", action="store_true", help="Also write Markdown report")
    p.add_argument("--output", "-o", default="reports", help="Output directory")
    p.add_argument("--target", default="unspecified")
    p.add_argument("--origin", default="unspecified", help="Authorized origin")
    p.add_argument("--scope", default="Authorized lab assessment scope as configured by the operator.")
    p.add_argument("--assessment-date", default=None)
    p.add_argument("--scan-id", default=None)
    p.add_argument("--scanner-version", default="0.1.0")
    p.add_argument(
        "--no-cvss-suggestions",
        action="store_true",
        help="Do not apply analyst-assessed default vectors",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Fail when validation errors occur",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.xss and not args.sqli and not args.misconfig and not args.input:
        print("error: provide at least one of --xss/--sqli/--misconfig/--input", file=sys.stderr)
        return 2

    formats = list(args.format) if args.format else ["html", "json", "md"]
    if args.pdf and "pdf" not in formats:
        formats.append("pdf")
    if getattr(args, "md", False) and "md" not in formats:
        formats.append("md")

    try:
        result = run_report_module(
            xss_path=args.xss,
            sqli_path=args.sqli,
            misconfig_path=args.misconfig,
            extra_paths=args.input,
            output_dir=args.output,
            formats=formats,
            pdf=args.pdf or ("pdf" in formats),
            target=args.target,
            authorized_origin=args.origin,
            scope=args.scope,
            assessment_date=args.assessment_date,
            scan_id=args.scan_id,
            scanner_version=args.scanner_version,
            apply_cvss_suggestions=not args.no_cvss_suggestions,
            strict=args.strict,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = [i for i in result.issues if i.level == "error"]
    if args.strict and errors:
        print(f"validation failed with {len(errors)} error(s)", file=sys.stderr)
        for i in errors[:20]:
            print(f"  - {i.source}: {i.message}", file=sys.stderr)
        return 3

    print(
        f"wrote report with {len(result.findings)} unique findings "
        f"(incomplete={result.incomplete}) -> {args.output}"
    )
    for kind, path in result.outputs.items():
        print(f"  {kind}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
