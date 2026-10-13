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
from vulnsight.ui import Console


def _console(args: argparse.Namespace) -> Console:
    return Console(no_color=bool(getattr(args, "no_color", False)))


def _cmd_version(args: argparse.Namespace) -> int:
    ui = _console(args)
    ui.banner(subtitle="version")
    ui.status_info(__version__)
    ui.print()
    return 0


def _cmd_docs(args: argparse.Namespace) -> int:
    """Open the interactive docs landing page in a browser."""
    import webbrowser

    ui = _console(args)
    path = (REPO_ROOT / "docs" / "index.html").resolve()
    if not path.is_file():
        ui.status_fail(f"docs landing page missing: {path}")
        return 1
    uri = path.as_uri()
    ui.banner(subtitle="interactive documentation")
    ui.status_ok(f"opening {path}")
    if not args.no_open:
        webbrowser.open(uri)
    ui.status_info(uri)
    ui.print()
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    ui = _console(args)
    ensure_module_paths()
    ui.render_doctor_header()
    ui.status_info(f"Python {sys.version.split()[0]}  ({sys.executable})")
    ui.status_info(f"Repo root  {REPO_ROOT}")
    ui.print()
    ok = True

    if sys.version_info < (3, 10):
        ui.status_fail("Python 3.10+ required")
        ok = False
    else:
        ui.status_ok("Python version")

    for name, path in MODULE_DIRS.items():
        if path.is_dir():
            ui.status_ok(f"module dir {name}")
        else:
            ui.status_fail(f"missing module dir {name} → {path}")
            ok = False

    required = ["requests", "bs4", "flask", "jinja2", "cvss"]
    for pkg in required:
        try:
            __import__(pkg if pkg != "bs4" else "bs4")
            ui.status_ok(f"import {pkg}")
        except ImportError:
            ui.status_fail(f"missing package {pkg}")
            ok = False

    try:
        from xss.browser_verify import playwright_available

        if playwright_available():
            ui.status_ok("playwright available")
        else:
            ui.status_info("playwright not installed (browser XSS verify optional)")
    except Exception as exc:  # noqa: BLE001
        ui.status_info(f"browser verify check skipped ({exc})")

    ui.status_info(
        "No bundled vulnerable app — point vulnsight at your authorized local website"
    )
    ui.status_info(
        "Create a project file: vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT"
    )

    ui.render_doctor_footer(ok)
    return 0 if ok else 1


def _cmd_validate_input(args: argparse.Namespace) -> int:
    ui = _console(args)
    try:
        errors = validate_crawl_map_file(args.file)
    except Exception as exc:  # noqa: BLE001
        ui.status_fail(str(exc))
        return 1
    if errors:
        ui.status_fail("crawl_map validation failed")
        for e in errors:
            ui.hint(f"- {e}")
        return 1
    ui.banner(subtitle="crawl map validation")
    ui.status_ok(f"crawl map valid ({args.file})")
    ui.print()
    return 0


def _cmd_init_project(args: argparse.Namespace) -> int:
    ui = _console(args)
    try:
        path = write_project_template(
            args.output,
            target=args.target,
            project_name=args.name,
            project_path=args.project_path,
        )
    except Exception as exc:  # noqa: BLE001
        ui.status_fail(str(exc))
        return 1
    ui.banner(subtitle="authorized project created")
    ui.panel(
        "NEXT STEPS",
        [
            ("file", str(path)),
            ("edit", "authorization.authorized_by"),
            ("scan", f"vulnsight scan --project {path}"),
        ],
    )
    ui.print()
    ui.status_info(f'statement: "{REQUIRED_AUTH_PHRASE}"')
    ui.print()
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    ui = _console(args)
    log_level = logging.DEBUG if args.verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )
    if not args.verbose:
        # Keep the UI clean; module loggers often default to INFO.
        logging.getLogger("web_vuln").setLevel(logging.ERROR)
        logging.getLogger("vulnsight").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)

    project = None
    if args.project:
        try:
            project = load_project_file(args.project)
        except ProjectError as exc:
            ui.status_fail(f"project error: {exc}")
            return 2

    if project is None and not args.target:
        ui.status_fail("provide --project FILE or --target URL")
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
        if args.skip_modules:
            skip = {m.strip() for m in args.skip_modules.split(",") if m.strip()}
            cfg.modules = [m for m in cfg.modules if m not in skip]

        scope_label = (
            "external-authorized"
            if cfg.allow_external
            else "lab-loopback (authorized project)"
        )
        ui.render_scan_header(
            target=cfg.target,
            scope=scope_label,
            modules=cfg.modules,
            output=cfg.output_dir,
            project=project.project_name,
            authorized_by=project.authorized_by,
            codebase=project.project_path,
        )
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
        if args.allow_external:
            ui.status_warn(
                "external target mode enabled — use only with written authorization"
            )

        ui.render_scan_header(
            target=args.target,
            scope=scope_label,
            modules=modules,
            output=args.output,
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

    try:
        result = run_scan(cfg)
    except ScopeError as exc:
        ui.status_fail(f"scope error: {exc}")
        ui.hint(
            "use an authorized project file for local/private targets:\n"
            "  vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT\n"
            "  vulnsight scan --project myproject.json"
        )
        return 2
    except Exception as exc:  # noqa: BLE001
        ui.status_fail(str(exc))
        return 1

    ui.render_scan_result(result)
    return result.exit_code



def _cmd_compare(args: argparse.Namespace) -> int:
    """Compare current findings against a secure baseline (academic control)."""
    ui = _console(args)
    from vulnsight.compare import compare_findings, write_compare_report

    ui.banner(subtitle="secure vs vulnerable comparison")
    try:
        result = compare_findings(args.current, args.baseline)
        paths = write_compare_report(result, args.output)
    except Exception as exc:  # noqa: BLE001
        ui.status_fail(str(exc))
        return 1
    ui.status_ok(
        f"new/regressed findings: {result['summary']['new_count']} "
        f"(current={result['current_findings']}, baseline={result['baseline_findings']})"
    )
    for kind, path in paths.items():
        ui.status_info(f"{kind}: {path}")
    ui.status_info(result["summary"]["interpretation"])
    ui.print()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    ui = _console(args)
    ensure_module_paths()
    from report_module import run_report_module

    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        ui.status_fail("input must be a findings list or object with findings[]")
        return 1

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    ui.banner(subtitle="report generation")
    result = run_report_module(
        findings_objects=findings,
        output_dir=args.output,
        formats=formats,
        target=args.target or "unspecified",
        authorized_origin=args.origin or "unspecified",
        scanner_version=__version__,
    )
    for kind, path in (result.outputs or {}).items():
        ui.status_ok(f"{kind}: {path}")
    ui.print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnsight",
        description=(
            "VulnSight — authorized modular web vulnerability scanner. "
            "Typical flow: init-project → scan --project FILE → open HTML report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "UI tip: colors auto-disable when piped or when NO_COLOR=1 / --no-color is set."
        ),
    )
    color_parent = argparse.ArgumentParser(add_help=False)
    color_parent.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (also respects NO_COLOR)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (also respects NO_COLOR)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("version", parents=[color_parent], help="Print scanner version")
    v.set_defaults(func=_cmd_version)

    docs = sub.add_parser(
        "docs",
        parents=[color_parent],
        help="Open the interactive VulnSight documentation landing page",
    )
    docs.add_argument(
        "--no-open",
        action="store_true",
        help="Print the docs path/URI without launching a browser",
    )
    docs.set_defaults(func=_cmd_docs)

    d = sub.add_parser(
        "doctor", parents=[color_parent], help="Check environment and lab readiness"
    )
    d.set_defaults(func=_cmd_doctor)

    vi = sub.add_parser(
        "validate-input",
        parents=[color_parent],
        help="Validate a crawl_map.json file",
    )
    vi.add_argument("--file", required=True, help="Path to crawl_map.json")
    vi.set_defaults(func=_cmd_validate_input)

    ip = sub.add_parser(
        "init-project",
        parents=[color_parent],
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
        parents=[color_parent],
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
    s.add_argument("--format", default="json,html,md,pdf", help="Report formats: json,html,md,pdf")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=_cmd_scan)

    c = sub.add_parser(
        "compare",
        parents=[color_parent],
        help="Compare current findings against a secure baseline (vulnerable vs secure demo)",
    )
    c.add_argument("--current", "-c", required=True, help="Current findings JSON")
    c.add_argument("--baseline", "-b", required=True, help="Secure baseline findings JSON")
    c.add_argument("--output", "-o", default="reports", help="Output directory")
    c.set_defaults(func=_cmd_compare)

    r = sub.add_parser(
        "report", parents=[color_parent], help="Generate reports from findings JSON"
    )
    r.add_argument("--input", "-i", required=True, help="findings.json or module ScanResult JSON")
    r.add_argument("--output", "-o", default="reports")
    r.add_argument("--format", default="json,html,md,pdf", help="Comma-separated: json,html,md,pdf")
    r.add_argument("--target", default="")
    r.add_argument("--origin", default="")
    r.set_defaults(func=_cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    # Allow `vulnsight --no-color <cmd>` by moving global flag onto the subcommand.
    if "--no-color" in argv_list:
        idx = argv_list.index("--no-color")
        # Keep one copy; argparse parents accept it on the subcommand.
        if idx == 0 and len(argv_list) > 1:
            cmd = argv_list[1]
            rest = argv_list[2:]
            argv_list = [cmd, "--no-color", *rest]
    parser = build_parser()
    args = parser.parse_args(argv_list)

    if getattr(args, "command", None) == "scan":
        args.output_set = any(a in {"-o", "--output"} for a in argv_list)
        args.max_pages_set = "--max-pages" in argv_list
        args.timeout_set = "--timeout" in argv_list
        args.max_requests_set = "--max-requests" in argv_list
        args.format_set = "--format" in argv_list

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
