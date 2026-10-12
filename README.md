# VulnSight — Modular Web Vulnerability Scanner

**See the weakness. Prove the risk. Secure the web.**

Linux-style CLI cybersecurity tool: clone → install → authorize a local website with a project file → scan with all modules → open the HTML/JSON report.

> **Authorization required.** Only scan systems you own or have explicit written permission to test. A project file is the preferred way to declare that authorization. Crawl-map URLs are not automatic permission to attack.

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

After this, the single command you use day-to-day is `vulnsight`.

## Scan an authorized local website

### 1) Start the site you own / are allowed to test

Example — built-in lab:

```bash
python target_app/app.py
# http://127.0.0.1:5001
```

Or start your own local web app on any loopback/private port.

### 2) Create an authorization project file

```bash
vulnsight init-project \
  -o myproject.json \
  --target http://127.0.0.1:5001 \
  --name "My Local App" \
  --project-path ./target_app
```

Edit `myproject.json` and set `authorization.authorized_by` to your name.
Keep `authorization.i_own_or_have_permission` set to `true` only if that is true.

Optional `project_path` points at the local application folder under test (metadata for the report/operators). VulnSight is a **dynamic web scanner**; it tests the running website URL, not source code as SAST.

### 3) Run all modules and generate the report

```bash
vulnsight scan --project myproject.json
```

That single command:

1. Validates your authorization project file
2. Runs recon + XSS + SQLi + command injection + access control + reporting
3. Writes:

- `reports/vulnsight_report.html` — human-readable findings
- `reports/findings.json` — machine-readable findings

Open the HTML report in a browser when the scan finishes.

### Lab shortcut (already authorized sample)

```bash
python target_app/app.py   # terminal A
vulnsight scan --project fixtures/sample_project.json   # terminal B
```

## Other useful commands

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
| `vulnsight/` | CLI, project authorization, orchestrator, scope |
| `Crawler/` | Recon → `crawl_map.json` |
| `xss_module/` | Reflected / stored XSS |
| `sqli_&_command_module/` | SQLi + simulated command injection |
| `access_control_module/` | IDOR + broken access control |
| `target_app/` | Deliberately vulnerable local Flask lab |
| `reporting_module/` | CVSS scoring + HTML/JSON reports |
| `fixtures/sample_project.json` | Example authorized project file |

## Tests

```bash
python -m pytest
```

## Documentation

- [Usage](docs/USAGE.md) · [Installation](docs/INSTALLATION.md) · [Demo runbook](docs/DEMO_RUNBOOK.md)
- [Architecture](docs/ARCHITECTURE.md) · [Vulnerable target](docs/VULNERABLE_TARGET.md)
- [Security](docs/SECURITY.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)

## License

MIT — see [LICENSE](LICENSE).
