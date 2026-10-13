"""End-to-end scan orchestration: recon → detect → report."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnsight import __version__
from vulnsight.config import ScanConfig
from vulnsight.paths import ensure_module_paths
from vulnsight.scope import origin_of, require_lab_target

log = logging.getLogger("vulnsight")

MODULE_STATUS_COMPLETED = "completed"
MODULE_STATUS_WARNINGS = "completed_with_warnings"
MODULE_STATUS_FAILED = "failed"
MODULE_STATUS_SKIPPED = "skipped"
MODULE_STATUS_UNSUPPORTED = "unsupported"


@dataclass
class ModuleRun:
    name: str
    status: str
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class OrchestratorResult:
    target: str
    output_dir: str
    module_runs: list[ModuleRun]
    findings: list[dict[str, Any]]
    crawl_map_path: str | None
    report_paths: dict[str, str]
    exit_code: int
    scope_mode: str = "lab-loopback"
    incomplete: bool = False

    def summary_lines(self) -> list[str]:
        confirmed = suspected = 0
        for f in self.findings:
            status = (f.get("verification_status") or "").lower()
            if status == "confirmed":
                confirmed += 1
            elif status in {"probable", "candidate"}:
                suspected += 1
        lines = [
            f"VulnSight {__version__} scan of {self.target}",
            f"Scope: {self.scope_mode}",
            (
                f"Findings: {len(self.findings)} total "
                f"({confirmed} confirmed, {suspected} suspected/probable/candidate)"
            ),
        ]
        if self.incomplete:
            lines.append(
                "Coverage: PARTIAL — one or more modules failed or were skipped"
            )
        for run in self.module_runs:
            extra = ""
            if run.errors:
                extra = f" error={run.errors[0][:120]}"
            elif run.detail:
                extra = f" ({run.detail})"
            lines.append(
                f"  [{run.status}] {run.name}: findings={run.findings_count}{extra}"
            )
        if self.report_paths:
            for kind, path in sorted(self.report_paths.items()):
                if kind in {"json", "html", "findings", "pdf", "md", "markdown"}:
                    lines.append(f"  report[{kind}]: {path}")
        return lines


def _enabled(cfg: ScanConfig, name: str) -> bool:
    return name in cfg.modules


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _finding_dicts(scan_result: Any) -> list[dict[str, Any]]:
    if scan_result is None:
        return []
    if hasattr(scan_result, "to_dict"):
        payload = scan_result.to_dict()
        return list(payload.get("findings") or [])
    if isinstance(scan_result, dict):
        return list(scan_result.get("findings") or [])
    return []


def run_scan(cfg: ScanConfig) -> OrchestratorResult:
    ensure_module_paths()
    target = require_lab_target(cfg.target, allow_external=cfg.allow_external)
    origin = origin_of(target)
    scope_mode = "external-authorized" if cfg.allow_external else "lab-loopback"
    out = Path(cfg.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    log.info("Starting scan target=%s scope=%s modules=%s", target, scope_mode, cfg.modules)

    module_runs: list[ModuleRun] = []
    all_findings: list[dict[str, Any]] = []
    crawl_map: dict[str, Any] | None = None
    crawl_map_path: str | None = cfg.crawl_map_path
    report_paths: dict[str, str] = {}
    failed_any = False
    executed: list[str] = []
    not_executed: list[str] = []
    failed_modules: list[str] = []

    # --- Recon ---
    if cfg.skip_recon or not _enabled(cfg, "recon"):
        if crawl_map_path and Path(crawl_map_path).is_file():
            crawl_map = json.loads(Path(crawl_map_path).read_text(encoding="utf-8"))
            module_runs.append(
                ModuleRun("recon", MODULE_STATUS_SKIPPED, detail="using provided crawl map")
            )
            not_executed.append("recon")
        elif not _enabled(cfg, "xss"):
            module_runs.append(
                ModuleRun("recon", MODULE_STATUS_SKIPPED, detail="disabled")
            )
            not_executed.append("recon")
        else:
            module_runs.append(
                ModuleRun(
                    "recon",
                    MODULE_STATUS_FAILED,
                    errors=["XSS enabled but no crawl map and recon disabled"],
                )
            )
            failed_any = True
            failed_modules.append("recon")
            not_executed.append("recon")
    else:
        try:
            from crawler_module import run_crawler_module

            out_crawl = str(out / "crawl_map.json")
            crawl_map = run_crawler_module(
                seed_url=target if target.endswith("/") else target + "/",
                allowed_origins=[origin],
                allow_loopback=cfg.allow_loopback or not cfg.allow_external,
                allow_private=False,
                max_pages=cfg.crawl_depth_pages,
                timeout=cfg.timeout,
                output_path=out_crawl,
                verbose=cfg.verbose,
            )
            crawl_map_path = out_crawl
            pages = len(crawl_map.get("pages") or [])
            module_runs.append(
                ModuleRun(
                    "recon",
                    MODULE_STATUS_COMPLETED,
                    detail=f"{pages} pages → {crawl_map_path}",
                )
            )
            executed.append("recon")
        except Exception as exc:  # noqa: BLE001
            log.exception("recon failed")
            crawl_map = None
            crawl_map_path = cfg.crawl_map_path
            module_runs.append(
                ModuleRun(
                    "recon",
                    MODULE_STATUS_FAILED,
                    errors=[str(exc)],
                )
            )
            failed_any = True
            failed_modules.append("recon")
            not_executed.append("recon")

    # --- XSS ---
    if not _enabled(cfg, "xss"):
        module_runs.append(ModuleRun("xss", MODULE_STATUS_SKIPPED, detail="disabled"))
        not_executed.append("xss")
    elif crawl_map is None and not crawl_map_path:
        module_runs.append(
            ModuleRun("xss", MODULE_STATUS_SKIPPED, detail="no crawl map available")
        )
        not_executed.append("xss")
    else:
        try:
            from xss_module import run_xss_module

            result = run_xss_module(
                crawl_map=crawl_map,
                crawl_map_path=None if crawl_map is not None else crawl_map_path,
                allowed_origins=[origin],
                allow_loopback=cfg.allow_loopback or not cfg.allow_external,
                marker_only=not cfg.enable_active_verify and not cfg.enable_metachar_probes,
                enable_active_verification=cfg.enable_active_verify,
                enable_stored_xss=cfg.enable_stored_xss,
                enable_browser_verification=cfg.enable_browser_verify,
                enable_metachar_probes=cfg.enable_metachar_probes,
                enable_extended_probes=cfg.enable_active_verify,
                timeout=cfg.timeout,
                max_requests=cfg.max_requests,
                verbose=cfg.verbose,
            )
            findings = _finding_dicts(result)
            all_findings.extend(findings)
            xss_path = out / "findings_xss.json"
            _write_json(xss_path, result.to_dict() if hasattr(result, "to_dict") else {"findings": findings})
            status = MODULE_STATUS_WARNINGS if getattr(result, "errors", None) else MODULE_STATUS_COMPLETED
            module_runs.append(
                ModuleRun("xss", status, findings_count=len(findings), errors=list(getattr(result, "errors", []) or []))
            )
            executed.append("xss")
        except Exception as exc:  # noqa: BLE001
            log.exception("xss failed")
            module_runs.append(
                ModuleRun("xss", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("xss")
            not_executed.append("xss")

    # --- SQLi ---
    if not _enabled(cfg, "sqli"):
        module_runs.append(ModuleRun("sqli", MODULE_STATUS_SKIPPED, detail="disabled"))
        not_executed.append("sqli")
    else:
        try:
            from sqli.detector import check_local_target as sqli_check

            result = sqli_check(
                target,
                crawl_map=crawl_map,
                timeout=cfg.timeout,
                max_requests=min(40, cfg.max_requests),
            )
            findings = _finding_dicts(result)
            all_findings.extend(findings)
            _write_json(out / "findings_sqli.json", result.to_dict())
            status = MODULE_STATUS_WARNINGS if result.errors else MODULE_STATUS_COMPLETED
            if result.errors and not findings:
                status = MODULE_STATUS_FAILED
                failed_any = True
                failed_modules.append("sqli")
            module_runs.append(
                ModuleRun("sqli", status, findings_count=len(findings), errors=list(result.errors))
            )
            if status != MODULE_STATUS_FAILED:
                executed.append("sqli")
            else:
                not_executed.append("sqli")
        except Exception as exc:  # noqa: BLE001
            log.exception("sqli failed")
            module_runs.append(
                ModuleRun("sqli", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("sqli")
            not_executed.append("sqli")

    # --- Command injection ---
    if not _enabled(cfg, "command_injection"):
        module_runs.append(
            ModuleRun("command_injection", MODULE_STATUS_SKIPPED, detail="disabled")
        )
        not_executed.append("command_injection")
    else:
        try:
            from command_injection.detector import check_local_target as cmd_check

            result = cmd_check(
                target,
                crawl_map=crawl_map,
                timeout=cfg.timeout,
                max_probes=12,
            )
            findings = _finding_dicts(result)
            all_findings.extend(findings)
            _write_json(out / "findings_command_injection.json", result.to_dict())
            status = MODULE_STATUS_WARNINGS if result.errors else MODULE_STATUS_COMPLETED
            if result.errors and not findings:
                status = MODULE_STATUS_FAILED
                failed_any = True
                failed_modules.append("command_injection")
            module_runs.append(
                ModuleRun(
                    "command_injection",
                    status,
                    findings_count=len(findings),
                    errors=list(result.errors),
                )
            )
            if status != MODULE_STATUS_FAILED:
                executed.append("command_injection")
            else:
                not_executed.append("command_injection")
        except Exception as exc:  # noqa: BLE001
            log.exception("command_injection failed")
            module_runs.append(
                ModuleRun("command_injection", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("command_injection")
            not_executed.append("command_injection")

    # --- Access control ---
    if not _enabled(cfg, "access_control"):
        module_runs.append(
            ModuleRun("access_control", MODULE_STATUS_SKIPPED, detail="disabled")
        )
        not_executed.append("access_control")
    else:
        try:
            from access_control.detector import check_local_target as ac_check

            result = ac_check(target, crawl_map=crawl_map)
            findings = _finding_dicts(result)
            all_findings.extend(findings)
            _write_json(out / "findings_access_control.json", result.to_dict())
            status = MODULE_STATUS_WARNINGS if result.errors else MODULE_STATUS_COMPLETED
            if result.errors and not findings:
                status = MODULE_STATUS_FAILED
                failed_any = True
                failed_modules.append("access_control")
            module_runs.append(
                ModuleRun(
                    "access_control",
                    status,
                    findings_count=len(findings),
                    errors=list(result.errors),
                )
            )
            if status != MODULE_STATUS_FAILED:
                executed.append("access_control")
            else:
                not_executed.append("access_control")
        except Exception as exc:  # noqa: BLE001
            log.exception("access_control failed")
            module_runs.append(
                ModuleRun("access_control", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("access_control")
            not_executed.append("access_control")


    # --- Misconfiguration / hygiene ---
    if not _enabled(cfg, "misconfig"):
        module_runs.append(
            ModuleRun("misconfig", MODULE_STATUS_SKIPPED, detail="disabled")
        )
        not_executed.append("misconfig")
    else:
        try:
            from misconfig.detector import check_local_target as misconfig_check

            result = misconfig_check(
                target,
                crawl_map=crawl_map,
                timeout=cfg.timeout,
                max_requests=min(20, cfg.max_requests),
            )
            findings = _finding_dicts(result)
            all_findings.extend(findings)
            _write_json(out / "findings_misconfig.json", result.to_dict())
            status = MODULE_STATUS_WARNINGS if result.errors else MODULE_STATUS_COMPLETED
            if result.errors and not findings:
                status = MODULE_STATUS_FAILED
                failed_any = True
                failed_modules.append("misconfig")
            module_runs.append(
                ModuleRun(
                    "misconfig",
                    status,
                    findings_count=len(findings),
                    errors=list(result.errors),
                )
            )
            if status != MODULE_STATUS_FAILED:
                executed.append("misconfig")
            else:
                not_executed.append("misconfig")
        except Exception as exc:  # noqa: BLE001
            log.exception("misconfig failed")
            module_runs.append(
                ModuleRun("misconfig", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("misconfig")
            not_executed.append("misconfig")

    # Combined findings dump (pre-report)
    combined_path = out / "findings_raw.json"
    _write_json(
        combined_path,
        {
            "scanner_version": __version__,
            "target": target,
            "module_runs": [
                {
                    "name": r.name,
                    "status": r.status,
                    "findings_count": r.findings_count,
                    "errors": r.errors,
                    "detail": r.detail,
                }
                for r in module_runs
            ],
            "findings": all_findings,
        },
    )

    # --- Reporting ---
    if not _enabled(cfg, "reporting"):
        module_runs.append(
            ModuleRun("reporting", MODULE_STATUS_SKIPPED, detail="disabled")
        )
        not_executed.append("reporting")
        report_paths["findings_raw"] = str(combined_path)
    else:
        try:
            from report_module import run_report_module

            formats = list(cfg.formats) or ["json", "html"]
            extra_limits: list[str] = []
            if failed_modules:
                extra_limits.append(
                    "Failed modules (findings from other modules may still be valid): "
                    + ", ".join(failed_modules)
                )
            extra_limits.append(
                "Assessment quality note: candidate/probable findings require analyst review; "
                "absence of findings is not a security certification. See docs/THREAT_MODEL.md."
            )
            report = run_report_module(
                findings_objects=all_findings,
                output_dir=str(out),
                formats=formats,
                target=target,
                authorized_origin=origin,
                scope=(
                    "Authorized VulnSight lab assessment (loopback by default). "
                    "Do not treat crawler-discovered URLs as permission to test them."
                ),
                scanner_version=__version__,
                modules_executed=executed,
                modules_not_executed=not_executed,
                apply_cvss_suggestions=True,
                extra_limitations=extra_limits,
                mark_incomplete=bool(failed_modules),
            )
            outputs = dict(getattr(report, "outputs", {}) or {})
            report_paths.update(outputs)
            # Stable alias expected by docs / CLI consumers
            src_json = outputs.get("json")
            if src_json:
                alias = out / "findings.json"
                alias.write_text(Path(src_json).read_text(encoding="utf-8"), encoding="utf-8")
                report_paths["findings"] = str(alias)
            report_paths["findings_raw"] = str(combined_path)
            report_findings = getattr(report, "findings", None) or []
            if report_findings:
                # Prefer canonical unique findings for UI totals.
                normalized: list[dict] = []
                for f in report_findings:
                    d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
                    if not d.get("module") and d.get("source_module"):
                        d["module"] = d["source_module"]
                    normalized.append(d)
                all_findings = normalized
            artifact_kinds = [
                k for k in ("html", "md", "pdf", "json", "findings") if k in report_paths
            ]
            module_runs.append(
                ModuleRun(
                    "reporting",
                    MODULE_STATUS_COMPLETED,
                    findings_count=len(all_findings),
                    detail="artifacts: " + ", ".join(artifact_kinds),
                )
            )
            executed.append("reporting")
        except Exception as exc:  # noqa: BLE001
            log.exception("reporting failed")
            module_runs.append(
                ModuleRun("reporting", MODULE_STATUS_FAILED, errors=[str(exc)])
            )
            failed_any = True
            failed_modules.append("reporting")
            report_paths["findings_raw"] = str(combined_path)

    # Exit codes: 0 ok, 1 module failure, 2 scope/config error (raised earlier)
    exit_code = 1 if failed_any else 0
    incomplete = bool(failed_modules or any(r.status == MODULE_STATUS_SKIPPED for r in module_runs))
    return OrchestratorResult(
        target=target,
        output_dir=str(out),
        module_runs=module_runs,
        findings=all_findings,
        crawl_map_path=crawl_map_path,
        report_paths=report_paths,
        exit_code=exit_code,
        scope_mode=scope_mode,
        incomplete=incomplete,
    )


def validate_crawl_map_file(path: str) -> list[str]:
    ensure_module_paths()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        from xss.crawl_map_schema import validate_crawl_map

        return validate_crawl_map(data)
    except Exception:
        from crawler.schema import validate_crawl_map

        return validate_crawl_map(data)
