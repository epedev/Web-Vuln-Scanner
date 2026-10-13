# Usage

## Authorized-use warning

Only scan systems you own or have explicit written permission to test. VulnSight defaults to loopback (`127.0.0.1` / `localhost` / `::1`). Crawler-discovered URLs are **not** authorization.

VulnSight does not include a vulnerable target application. Start your own prepared local website first.

## Authorized project scan (recommended)

```bash
# Create a project/authorization file for the local website under test
vulnsight init-project -o myproject.json \
  --target http://127.0.0.1:5001 \
  --project-path /path/to/your/app

# Edit authorized_by, then run every module and generate reports
vulnsight scan --project myproject.json
```

The project JSON is your authorization record + target configuration. Optional `project_path` is metadata about the local codebase; scanning still hits the live URL.

## Direct URL scan (lab loopback)

```bash
vulnsight scan --target http://127.0.0.1:5001 --output ./reports -v
```

Artifacts:

- `reports/crawl_map.json`
- `reports/findings_*.json` (per module)
- `reports/findings.json` (normalized alias)
- `reports/vulnsight_report.html`
- `reports/vulnsight_report.md`
- `reports/vulnsight_report.pdf`

## CLI reference

```bash
vulnsight version
vulnsight doctor
vulnsight docs                 # open interactive docs/index.html
vulnsight docs --no-open      # print path/URI only
vulnsight validate-input --file fixtures/sample_crawl_map.json
vulnsight scan --target http://127.0.0.1:5001 --output ./reports
vulnsight report --input ./reports/findings.json --format html --output ./reports
vulnsight compare --current ./reports/findings.json \
  --baseline fixtures/secure_baseline_findings.json --output ./reports
```

Interactive HTML reports (`vulnsight_report.html`) include sticky navigation, severity chips, and client-side search.

Useful `scan` flags:

| Flag | Purpose |
|------|---------|
| `--project FILE` | Authorized project JSON (preferred) |
| `--modules recon,xss,sqli,...` | Run a subset |
| `--skip-modules reporting` | Skip a module |
| `--crawl-map PATH` | Reuse a crawl map (skips recon) |
| `--marker-only` | XSS marker-only mode |
| `--browser-verify` | Optional Playwright confirmation |
| `--allow-external` | Permit non-loopback targets (explicit) |
| `--no-color` | Disable terminal colors |
| `--max-pages` / `--max-requests` / `--timeout` | Budgets |

## Module-only workflows

Member modules remain independently runnable; see each module README under `Crawler/`, `xss_module/`, `sqli_&_command_module/`, `access_control_module/`, and `reporting_module/`.
