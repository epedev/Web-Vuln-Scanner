# Architecture

VulnSight is a modular monorepo integrated by a thin CLI/orchestrator.

```
vulnsight scan
    │
    ├─ scope.require_lab_target()     # fail-closed loopback default
    ├─ Crawler → crawl_map.json v1.0
    ├─ xss_module.run_xss_module()
    ├─ sqli.detector.check_local_target()
    ├─ command_injection.detector.check_local_target()
    ├─ access_control.detector.check_local_target()
    └─ reporting_module.run_report_module()
```

## Five-person ownership

| Member | Path | Contract |
|--------|------|----------|
| 1 Recon | `Crawler/` | `crawl_map.json` schema v1.0 |
| 2 Injection | `sqli_&_command_module/` | `ScanResult` / `Finding` |
| 3 XSS | `xss_module/` | `ScanResult` + crawl map consumer |
| 4 Auth/AC | `access_control_module/` | `ScanResult` / lab identities |
| 5 Lab + reporting | `target_app/`, `reporting_module/` | Flask lab + canonical findings |

## Shared models

- Detection findings: `xss_module/scanner/models.py` (`Finding`, `ScanResult`)
- Reporting canonical schema: `reporting_module/reporting/schema.py`
- Orchestrator adds member directories to `sys.path` via `vulnsight/paths.py`

## Safety

- Explicit `--target` required
- Default allowlist: `127.0.0.1` / `localhost` over HTTP
- Redirects re-checked inside crawler and XSS HTTP engines
- Command-injection lab is **simulated** (no OS shell)
