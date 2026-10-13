# Reporting Module

VulnSight reporting and CVSS v3.1 risk-scoring engine.

Aggregates JSON findings from XSS, SQLi, and misconfiguration sources into a validated canonical schema, deduplicates conservatively, scores CVSS v3.1, and writes professional HTML (optional PDF) assessment reports.

## Setup

```bash
cd reporting_module
python -m pip install -r requirements.txt
# Optional PDF:
# python -m pip install weasyprint
```

## Generate a report

```bash
python report_module.py \
  --xss fixtures/findings_xss.json \
  --sqli fixtures/findings_sqli.json \
  --misconfig fixtures/findings_misconfig.json \
  --target http://127.0.0.1:5001 \
  --origin http://127.0.0.1:5001 \
  --format html --format json \
  -o reports/
```

Outputs:

- `reports/vulnsight_report.html`
- `reports/normalized_findings.json`
- `reports/vulnsight_report.md`
- `reports/vulnsight_report.pdf` (WeasyPrint or ReportLab)

## Programmatic API

```python
from report_module import run_report_module

result = run_report_module(
    xss_path="fixtures/findings_xss.json",
    sqli_path="fixtures/findings_sqli.json",
    misconfig_path="fixtures/findings_misconfig.json",
    output_dir="reports",
)
print(result.summary)
```

## Tests

```bash
pytest -q
```

## Docs

- [REPORTING_MODULE.md](docs/REPORTING_MODULE.md) — architecture, CVSS method, CLI
- [FINDINGS_SCHEMA.md](docs/FINDINGS_SCHEMA.md) — canonical schema / adapters

## Notes

- Fixture data is synthetic unless you substitute live module outputs.
- Modules that were not executed are disclosed; they are never implied as “clean”.
- CVSS suggestions without a module-provided vector are labeled `analyst_assessed`.
