# Usage

## Authorized-use warning

Only scan systems you own or have explicit written permission to test. VulnSight defaults to the local lab (`127.0.0.1` / `localhost`). Crawler-discovered URLs are **not** authorization.

## Start the lab

```bash
# Terminal A
python target_app/app.py
# Lab: http://127.0.0.1:5001
```

Stop with `Ctrl+C`. The lab binds loopback only by default.

## Authorized project scan (recommended)

```bash
# Create a project/authorization file for the local website under test
vulnsight init-project -o myproject.json --target http://127.0.0.1:5001 --project-path ./target_app

# Edit authorized_by, then run every module and generate reports
vulnsight scan --project myproject.json
```

The project JSON is your authorization record + target configuration. It can also point at the local app folder via `project_path` (operator metadata; scanning still hits the live URL).

## Direct URL scan (lab loopback)

```bash
# Terminal B
vulnsight scan --target http://127.0.0.1:5001 --output ./reports -v
```

Artifacts:

- `reports/crawl_map.json`
- `reports/findings_*.json` (per module)
- `reports/findings.json` (normalized alias)
- `reports/vulnsight_report.html`

## CLI reference

```bash
vulnsight version
vulnsight doctor
vulnsight validate-input --file fixtures/sample_crawl_map.json
vulnsight scan --target http://127.0.0.1:5001 --output ./reports
vulnsight report --input ./reports/findings.json --format html --output ./reports
```

Useful `scan` flags:

| Flag | Purpose |
|------|---------|
| `--modules recon,xss,sqli,...` | Run a subset |
| `--skip-modules reporting` | Skip a module |
| `--crawl-map PATH` | Reuse a crawl map (skips recon) |
| `--marker-only` | XSS reflection markers only |
| `--browser-verify` | Optional Playwright confirmation |
| `--allow-external` | Permit non-loopback targets (explicit) |
| `--max-pages` / `--max-requests` / `--timeout` | Budgets |

## Module-only workflows

Member modules remain independently runnable; see each module README under `Crawler/`, `xss_module/`, `sqli_&_command_module/`, `access_control_module/`, and `reporting_module/`.
