# VulnSight — Intelligent Web Vulnerability Scanner

Modular web vulnerability scanner for **authorized** cybersecurity lab testing and academic assessment.

> **Authorization required.** Only scan systems you own or have explicit written permission to test. Crawl-map URLs are not automatic authorization.

## Repository layout

| Module | Description | Entry point |
|--------|-------------|-------------|
| [`Crawler/`](Crawler/) | Same-origin crawler producing XSS-compatible `crawl_map.json` | `crawler_module.py` |
| [`xss_module/`](xss_module/) | Reflected / stored XSS detection with scope controls and context-aware analysis | `xss_module.py` |
| [`sqli_&_command_module/`](sqli_&_command_module/) | SQL injection and OS command-injection checks (local lab) | `sqli/detector.py`, `command_injection/detector.py` |
| [`reporting_module/`](reporting_module/) | Finding aggregation, CVSS v3.1 scoring, HTML/PDF reports | `report_module.py` |

Shared finding model (used across modules): `xss_module/scanner/models.py`.

## Requirements

- Python 3.10+
- See root [`requirements.txt`](requirements.txt) or each module’s own `requirements.txt`

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Quick start (demo path)

### 1) Crawl → XSS scan

```bash
# Terminal A — loopback-only vulnerable app
python xss_module/fixtures/vulnerable_app/app.py

# Terminal B — discover input points
cd Crawler
python crawler_module.py \
  --seed http://127.0.0.1:5001/ \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  -o crawl_map.json -v

# Terminal B — XSS detection
cd ../xss_module
python xss_module.py \
  --crawl-map ../Crawler/crawl_map.json \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  --active-verify --metachar-probes --extended-probes \
  --enable-stored-xss \
  -o ../findings_xss.json -v
```

(You can also use `xss_module/fixtures/sample_crawl_map.json` without crawling.)

### 2) Generate an assessment report

Uses packaged fixtures (or replace with live module JSON outputs):

```bash
cd reporting_module
python report_module.py \
  --xss fixtures/findings_xss.json \
  --sqli fixtures/findings_sqli.json \
  --misconfig fixtures/findings_misconfig.json \
  --target http://127.0.0.1:5001 \
  --origin http://127.0.0.1:5001 \
  --format html --format json \
  -o reports/
```

Open `reporting_module/reports/vulnsight_report.html`.

Optional PDF (requires WeasyPrint system deps):

```bash
python report_module.py --xss fixtures/findings_xss.json --pdf -o reports/
```

### 3) Run tests

```bash
# From repository root
python -m pytest -q Crawler/tests
python -m pytest -q xss_module/tests
python -m pytest -q reporting_module/tests
PYTHONPATH="sqli_&_command_module:xss_module" python -m pytest -q 'sqli_&_command_module/tests'
```

## Design principles

- **Fail-closed scope** for active testing (explicit origins; loopback/private opt-in)
- **Evidence over assumptions** (candidate / probable / confirmed kept distinct)
- **CVSS v3.1** for reporting scores (incomplete vectors remain unscored)
- **Safe reporting** (HTML escaping, credential redaction, offline self-contained reports)
- **Modular integration** (JSON findings in → unified report out)

## Documentation

- [Crawler](Crawler/docs/CRAWLER.md)
- [XSS module](xss_module/docs/XSS_MODULE.md)
- [Reporting module](reporting_module/docs/REPORTING_MODULE.md)
- [Findings schema](reporting_module/docs/FINDINGS_SCHEMA.md)
- [SQLi module](sqli_&_command_module/docs/SQLI.md)
- [Command injection](sqli_&_command_module/docs/COMMAND_INJECTION.md)
- [Authorized use](SECURITY.md)

## Project status

Cybersecurity graduation project. Modules are independently usable; full CLI orchestration across all detectors is evolving. Synthetic reporting fixtures are clearly labeled and must not be presented as results from a real production assessment.

## License

MIT — see [LICENSE](LICENSE).
