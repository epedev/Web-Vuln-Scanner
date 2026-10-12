# VulnSight — Modular Web Vulnerability Scanner

**See the weakness. Prove the risk. Secure the web.**

CLI-first scanner with an integrated deliberately vulnerable Flask lab for authorized cybersecurity education.

> **Authorization required.** Only scan systems you own or have explicit written permission to test. Crawl-map URLs are not automatic authorization. Default scope is loopback lab only.

## Install

```bash
git clone https://github.com/epedev/Web-Vuln-Scanner.git
cd Web-Vuln-Scanner

python3 -m venv .venv
source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

vulnsight --help
vulnsight doctor
```

## Quick demo (integrated lab)

```bash
# Terminal A — team lab (loopback only)
python target_app/app.py
# → http://127.0.0.1:5001

# Terminal B — full recon → detect → report
vulnsight scan --target http://127.0.0.1:5001 --output ./reports -v
```

Open `reports/vulnsight_report.html` and `reports/findings.json`.

```bash
vulnsight validate-input --file fixtures/sample_crawl_map.json
vulnsight report --input ./reports/findings.json --format html --output ./reports
```

## Repository layout

| Path | Owner focus | Role |
|------|-------------|------|
| [`vulnsight/`](vulnsight/) | Integration | CLI + orchestrator + scope |
| [`Crawler/`](Crawler/) | Member 1 | Recon → `crawl_map.json` |
| [`sqli_&_command_module/`](sqli_&_command_module/) | Member 2 | SQLi + command injection |
| [`xss_module/`](xss_module/) | Member 3 | Reflected / stored XSS |
| [`access_control_module/`](access_control_module/) | Member 4 | IDOR + broken access control |
| [`target_app/`](target_app/) + [`reporting_module/`](reporting_module/) | Member 5 | Lab + reports / CVSS |

Shared detection model: `xss_module/scanner/models.py`.

## Tests

```bash
python -m pytest
```

Focused suites remain available under each module’s `tests/` directory.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Findings schema](docs/FINDINGS_SCHEMA.md)
- [Vulnerable target](docs/VULNERABLE_TARGET.md)
- [Graduation demo runbook](docs/DEMO_RUNBOOK.md)
- [Module guide](docs/MODULE_GUIDE.md)
- [Security / authorized use](docs/SECURITY.md) · root [SECURITY.md](SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Contributing](docs/CONTRIBUTING.md)

## Design principles

- Fail-closed loopback scope by default (`--allow-external` is explicit)
- Evidence over assumptions (candidate / probable / confirmed kept distinct)
- Defensible CVSS only; otherwise unscored
- Sanitized HTML reports and redacted secrets
- Modules stay independently testable; CLI calls documented Python APIs

## License

MIT — see [LICENSE](LICENSE).
