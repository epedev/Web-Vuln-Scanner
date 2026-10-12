# VulnSight Reporting & Risk-Scoring Module

## Architecture

```
Module JSON (XSS / SQLi / Misconfig)
  → ingestion.py
  → normalization.py (+ redaction, classification, CVSS)
  → deduplication.py
  → risk.py (sort + operational priority + summary)
  → html_report.py / pdf_report.py
  → report_module.py (CLI / API)
```

Product branding: **VulnSight — Intelligent Web Vulnerability Scanner**

## CVSS v3.1 methodology

- Scoring uses the maintained Python `cvss` library against complete CVSS:3.1 base vectors.
- Required metrics: AV, AC, PR, UI, S, C, I, A.
- Incomplete vectors are **not** scored by inventing metrics (`unscored` / `invalid` / `pending_assessment`).
- Score `0.0` is distinct from a missing score (`null`).
- Severity bands: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.
- When modules omit vectors, optional **analyst_assessed** class defaults may be applied (`--no-cvss-suggestions` disables). These are provisional and disclosed in the report.

Operational priority (`immediate` / `high` / `investigate` / …) is **not** a CVSS score.

## Deduplication policy

Merge only when all match:

- normalized vulnerability class (reflected XSS ≠ stored XSS ≠ SQLi)
- HTTP method
- base URL (scheme/host/path; query sorted for equivalence checks elsewhere)
- parameter
- location

Provenance (`source_ids`, `source_files`) is retained. Uncertain equivalence → keep separate.

## Commands

```bash
cd reporting_module
python -m pip install -r requirements.txt

python report_module.py \
  --xss fixtures/findings_xss.json \
  --sqli fixtures/findings_sqli.json \
  --misconfig fixtures/findings_misconfig.json \
  --format html --format json \
  --target http://127.0.0.1:5001 \
  --origin http://127.0.0.1:5001 \
  --output reports/

# Optional PDF (requires weasyprint)
python report_module.py --xss fixtures/findings_xss.json --pdf -o reports/
```

Programmatic:

```python
from report_module import run_report_module
result = run_report_module(
    xss_path="fixtures/findings_xss.json",
    sqli_path="fixtures/findings_sqli.json",
    misconfig_path="fixtures/findings_misconfig.json",
    output_dir="reports",
)
```

## Tests

```bash
cd reporting_module && pytest -q
```

## Outputs

- `reports/vulnsight_report.html`
- `reports/normalized_findings.json`
- `reports/vulnsight_report.pdf` (optional)

## Limitations

- Misconfiguration inputs currently use documented fixtures (module may not exist yet).
- Analyst-assessed CVSS defaults are not lab-measured.
- Offline CWE allowlist is not live MITRE validation.
- PDF depends on optional WeasyPrint system libraries.
