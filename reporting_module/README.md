# Reporting Module (VulnSight)

Advanced reporting and CVSS v3.1 risk-scoring engine for the modular web vulnerability scanner.

## Quick start

```bash
python -m pip install -r requirements.txt
python report_module.py \
  --xss fixtures/findings_xss.json \
  --sqli fixtures/findings_sqli.json \
  --misconfig fixtures/findings_misconfig.json \
  --format html --format json \
  --output reports/
pytest -q
```

Entry point: `report_module.py` · API: `run_report_module()`

Docs: [docs/REPORTING_MODULE.md](docs/REPORTING_MODULE.md) · [docs/FINDINGS_SCHEMA.md](docs/FINDINGS_SCHEMA.md)
