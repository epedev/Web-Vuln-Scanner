"""VulnSight CLI entry point (`vulnsight`)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from vulnsight import __version__
from vulnsight.config import ALL_MODULES, ScanConfig
from vulnsight.orchestrator import run_scan, validate_crawl_map_file
from vulnsight.paths import MODULE_DIRS, REPO_ROOT, ensure_module_paths
from vulnsight.project import (
    REQUIRED_AUTH_PHRASE,
    ProjectError,
    load_project_file,
    write_project_template,
)
from vulnsight.scope import ScopeError


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _cmd_doctor(_: argparse.Namespace) -> int:
    ensure_module_paths()
    print(f"VulnSight doctor — version {__version__}")
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    print(f"Repo root: {REPO_ROOT}")
    ok = True

    if sys.version_info < (3, 10):
        print("FAIL: Python 3.10+ required")
        ok = False
    else:
        print("OK: Python version")

    for name, path in MODULE_DIRS.items():
        if path.is_dir():
            print(f"OK: module dir {name} → {path}")
        else:
            print(f"FAIL: missing module dir {name} → {path}")
            ok = False

    required = ["requests", "bs4", "flask", "jinja2", "cvss"]
    for pkg in required:
        try:
            __import__(pkg if pkg != "bs4" else "bs4")
            print(f"OK: import {pkg}")
        except ImportError:
            print(f"FAIL: missing package {pkg}")
            ok = False

    try:
        from xss.browser_verify import playwright_available

        print(
            "OK: playwright available"
            if playwright_available()
            else "INFO: playwright not installed (browser XSS verify optional)"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"INFO: browser verify check skipped ({exc})")

    lab = MODULE_DIRS["target_app"] / "app.py"
    if lab.is_file():
        print(f"OK: lab app present ({lab})")
        print("INFO: start lab with: python target_app/app.py")
    else:
        print(f"FAIL: lab app missing at {lab}")
        ok = False

    print("RESULT:", "ready" if ok else "not ready")
    return 0 if ok else 1


def _cmd_validate_input(args: argparse.Namespace) -> int:
    try:
        errors = validate_crawl_map_file(args.file)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("crawl_map validation failed:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: crawl map valid ({args.file})")
    return 0


def _cmd_init_project(args: argparse.Namespace) -> int:
    try:
        path = write_project_template(
            args.output,
            target=args.target,
            project_name=args.name,
            project_path=args.project_path,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote authorized project file: {path}")
    print("Edit authorization.authorized_by, then run:")
    print(f"  vulnsight scan --project {path}")
    print(f'Required statement if included:\n  "{REQUIRED_AUTH_PHRASE}"')
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    project = None
    if args.project:
        try:
            project = load_project_file(args.project)
        except ProjectError as exc:
            print(f"project error: {exc}", file=sys.stderr)
            return 2

    if project is None and not args.target:
        print(
            "error: provide --project FILE or --target URL",
            file=sys.stderr,
        )
        return 2

    if project is not None:
        cfg = project.to_scan_config(verbose=args.verbose)
        if args.target:
            cfg.target = args.target
        if args.output_set:
            cfg.output_dir = args.output
        if args.modules:
            cfg.modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        if args.max_pages_set:
            cfg.crawl_depth_pages = args.max_pages
        if args.timeout_set:
            cfg.timeout = args.timeout
        if args.max_requests_set:
            cfg.max_requests = args.max_requests
        if args.allow_external:
            cfg.allow_external = True
        if args.crawl_map:
            cfg.crawl_map_path = args.crawl_map
            cfg.skip_recon = True
        if args.skip_recon:
            cfg.skip_recon = True
        if args.marker_only:
            cfg.enable_active_verify = False
            cfg.enable_metachar_probes = False
        if args.no_stored_xss:
            cfg.enable_stored_xss = False
        if args.browser_verify:
            cfg.enable_browser_verify = True
        if args.format_set:
            cfg.formats = [f.strip() for f in args.format.split(",") if f.strip()]

        print("VulnSight authorized project scan")
        print(f"  project: {project.project_name}")
        print(f"  file:    {project.path}")
        print(f"  target:  {cfg.target}")
        print(f"  auth by: {project.authorized_by}")
        if project.project_path:
            print(f"  codebase: {project.project_path}")
        print(f"  modules: {','.join(cfg.modules)}")
        print(f"  output:  {cfg.output_dir}")
    else:
        modules = list(ALL_MODULES)
        if args.modules:
            modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        if args.skip_modules:
            skip = {m.strip() for m in args.skip_modules.split(",") if m.strip()}
            modules = [m for m in modules if m not in skip]

        scope_label = (
            "external (--allow-external)"
            if args.allow_external
            else "lab-loopback (127.0.0.1/localhost/::1)"
        )
        print("VulnSight scan")
        print(f"  target:  {args.target}")
        print(f"  scope:   {scope_label}")
        print(f"  modules: {','.join(modules)}")
        print(f"  output:  {args.output}")
        if args.allow_external:
            print(
                "  WARNING: external target mode enabled — use only with written authorization.",
                file=sys.stderr,
            )

        cfg = ScanConfig(
            target=args.target,
            output_dir=args.output,
            modules=modules,
            crawl_depth_pages=args.max_pages,
            timeout=args.timeout,
            max_requests=args.max_requests,
            allow_external=args.allow_external,
            allow_loopback=True,
            verbose=args.verbose,
            enable_stored_xss=not args.no_stored_xss,
            enable_active_verify=not args.marker_only,
            enable_metachar_probes=not args.marker_only,
            enable_browser_verify=args.browser_verify,
            formats=[f.strip() for f in args.format.split(",") if f.strip()],
            crawl_map_path=args.crawl_map,
            skip_recon=args.skip_recon or bool(args.crawl_map),
        )

    if args.skip_modules and project is not None:
        skip = {m.strip() for m in args.skip_modules.split(",") if m.strip()}
        cfg.modules = [m for m in cfg.modules if m not in skip]

    try:
        result = run_scan(cfg)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        print(
            "hint: use an authorized project file for local/private targets:\n"
            "  vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT\n"
            "  vulnsight scan --project myproject.json",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("---")
    for line in result.summary_lines():
        print(line)
    html = result.report_paths.get("html")
    findings = result.report_paths.get("findings") or result.report_paths.get("json")
    if html:
        print(f"Open HTML report: {html}")
    if findings:
        print(f"Open JSON findings: {findings}")
    if result.exit_code != 0:
        print(
            "Scan finished with module failures (exit 1). "
            "Findings from successful modules were still written when available.",
            file=sys.stderr,
        )
    return result.exit_code


def _cmd_report(args: argparse.Namespace) -> int:
    ensure_module_paths()
    from report_module import run_report_module

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        print("error: input must be a findings list or object with findings[]", file=sys.stderr)
        return 1

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    result = run_report_module(
        findings_objects=findings,
        output_dir=args.output,
        formats=formats,
        target=args.target or "unspecified",
        authorized_origin=args.origin or "unspecified",
        scanner_version=__version__,
    )
    for kind, path in (result.outputs or {}).items():
        print(f"{kind}: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnsight",
        description=(
            "VulnSight — authorized modular web vulnerability scanner. "
            "Typical flow: init-project → scan --project FILE → open HTML report."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("version", help="Print scanner version")
    v.set_defaults(func=_cmd_version)

    d = sub.add_parser("doctor", help="Check environment and lab readiness")
    d.set_defaults(func=_cmd_doctor)

    vi = sub.add_parser("validate-input", help="Validate a crawl_map.json file")
    vi.add_argument("--file", required=True, help="Path to crawl_map.json")
    vi.set_defaults(func=_cmd_validate_input)

    ip = sub.add_parser(
        "init-project",
        help="Create an authorized project JSON file for a local website under test",
    )
    ip.add_argument(
        "-o",
        "--output",
        default="vulnsight-project.json",
        help="Output project file path",
    )
    ip.add_argument(
        "--target",
        default="http://127.0.0.1:5001",
        help="Website URL to authorize for scanning",
    )
    ip.add_argument("--name", default="authorized-local-target", help="Project name")
    ip.add_argument(
        "--project-path",
        help="Optional local folder of the app under test (metadata only; not SAST)",
    )
    ip.set_defaults(func=_cmd_init_project)

    s = sub.add_parser(
        "scan",
        help="Run all detection modules against an authorized target and write reports",
    )
    s.add_argument(
        "--project",
        "-p",
        help="Authorized project JSON file (preferred). Create with: vulnsight init-project",
    )
    s.add_argument(
        "--target",
        help="Target base URL (optional when --project is set)",
    )
    s.add_argument("--output", "-o", default="reports", help="Output directory")
    s.add_argument(
        "--modules",
        help="Comma-separated modules to run (default: all). "
        f"Choices: {','.join(ALL_MODULES)}",
    )
    s.add_argument("--skip-modules", help="Comma-separated modules to skip")
    s.add_argument("--max-pages", type=int, default=40, help="Crawler page budget")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--max-requests", type=int, default=200, help="XSS request budget")
    s.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow non-loopback targets (requires explicit authorization)",
    )
    s.add_argument("--crawl-map", help="Use existing crawl_map.json (skips recon)")
    s.add_argument("--skip-recon", action="store_true")
    s.add_argument("--marker-only", action="store_true", help="XSS marker-only mode")
    s.add_argument("--no-stored-xss", action="store_true")
    s.add_argument("--browser-verify", action="store_true", help="Optional Playwright XSS verify")
    s.add_argument("--format", default="json,html", help="Report formats: json,html[,pdf]")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("report", help="Generate reports from findings JSON")
    r.add_argument("--input", "-i", required=True, help="findings.json or module ScanResult JSON")
    r.add_argument("--output", "-o", default="reports")
    r.add_argument("--format", default="html,json")
    r.add_argument("--target", default="")
    r.add_argument("--origin", default="")
    r.set_defaults(func=_cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv_list)

    # Track whether the operator explicitly overrode defaults for project merges.
    if getattr(args, "command", None) == "scan":
        args.output_set = any(a in {"-o", "--output"} for a in argv_list)
        args.max_pages_set = "--max-pages" in argv_list
        args.timeout_set = "--timeout" in argv_list
        args.max_requests_set = "--max-requests" in argv_list
        args.format_set = "--format" in argv_list

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
