# VulnSight — Modular Web Vulnerability Scanner

**See the weakness. Prove the risk. Secure the web.**

Linux-style CLI cybersecurity tool: clone → install → authorize your local website with a project file → scan with all modules → open the HTML/JSON report.

> **Authorization required.** Only scan systems you own or have explicit written permission to test. VulnSight does **not** ship a vulnerable target application — bring your own authorized local website.

## Install (one-time)

```bash
git clone https://github.com/epedev/Web-Vuln-Scanner.git
cd Web-Vuln-Scanner

python3 -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

vulnsight doctor
```

## Scan your authorized local website

```bash
# 1) Start YOUR prepared vulnerable / test website locally
#    example: http://127.0.0.1:5001

# 2) Create an authorization project file
vulnsight init-project \
  -o myproject.json \
  --target http://127.0.0.1:5001 \
  --name "My Local App" \
  --project-path /path/to/your/app

# 3) Edit authorization.authorized_by, then scan all modules + report
vulnsight scan --project myproject.json
```

Reports:

- `reports/vulnsight_report.html`
- `reports/findings.json`

## Other commands

```bash
vulnsight --help
vulnsight version
vulnsight doctor
vulnsight scan --target http://127.0.0.1:5001 -o ./reports
vulnsight report --input ./reports/findings.json --format html -o ./reports
```

## Repository layout

| Path | Role |
|------|------|
| `vulnsight/` | CLI, project authorization, orchestrator, scope, terminal UI |
| `Crawler/` | Recon → `crawl_map.json` |
| `xss_module/` | Reflected / stored XSS |
| `sqli_&_command_module/` | SQLi + command injection checks |
| `access_control_module/` | IDOR + broken access control |
| `reporting_module/` | CVSS scoring + HTML/JSON reports |
| `fixtures/sample_project.json` | Example authorized project file |

## Tests

```bash
python -m pytest
```

Live integration against your own lab (optional):

```bash
export VULNSIGHT_LAB_URL=http://127.0.0.1:5001
python -m pytest tests/integration -q
```

## Documentation

- [Usage](docs/USAGE.md) · [Installation](docs/INSTALLATION.md) · [Demo runbook](docs/DEMO_RUNBOOK.md)
- [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)

## License

MIT — see [LICENSE](LICENSE).
