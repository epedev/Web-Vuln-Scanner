# VulnSight Canonical Findings Schema v1.0

## Purpose

Unified finding model consumed by the reporting engine after module-specific ingestion.

Timestamps use **UTC ISO-8601**.

## Top-level report JSON

```json
{
  "schema_version": "1.0",
  "metadata": {},
  "summary": {},
  "findings": [],
  "issues": [],
  "limitations": [],
  "modules_executed": [],
  "modules_not_executed": [],
  "incomplete": false,
  "outputs": {}
}
```

## Canonical finding fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Stable unique id |
| `title` | string | Required |
| `vulnerability_type` | string | Required (e.g. `xss.reflected`, `SQL Injection`) |
| `source_module` | string | `xss` / `sqli` / `misconfig` / … |
| `url` | string | Required |
| `method` | string | HTTP method |
| `parameter` | string\|null | |
| `location` | string\|null | Context / header / etc. |
| `description` | string | |
| `evidence` | object | Redacted |
| `impact` | string | |
| `remediation` | string | |
| `severity` | string | Reporting severity (CVSS-derived when scored) |
| `module_severity` | string\|null | Original module estimate |
| `confidence` | string | |
| `verification_status` | string | Preserved from source (XSS never auto-promoted) |
| `cwe` | string\|null | |
| `owasp` | string\|null | OWASP Top 10 2021 |
| `cvss_version` | string\|null | `3.1` |
| `cvss_vector` | string\|null | Full base vector |
| `cvss_base_score` | number\|null | `null` means unscored (distinct from `0.0`) |
| `cvss_severity` | string\|null | None/Low/Medium/High/Critical |
| `cvss_status` | string | `scored` / `unscored` / `pending_assessment` / `invalid` |
| `cvss_provenance` | string | `calculated` / `analyst_assessed` / `module_provided` / `none` |
| `operational_priority` | string\|null | Non-CVSS priority label |
| `references` | string[] | |
| `timestamp` | string | UTC |
| `deduplication_key` | string | |
| `source_ids` | string[] | Provenance |
| `source_files` | string[] | Provenance |
| `original` | object | Redacted source record |
| `warnings` | string[] | |

## Module adapters

### XSS / SQLi (`ScanResult`)

Accepts:

```json
{ "module": "xss", "findings": [ /* scanner.models.Finding */ ], "outcomes": [], "limitations": [] }
```

Field mapping uses `module` → `source_module`, `context` → `location`.

### Misconfiguration

Same object shape (`findings` array). Fixtures used until a dedicated module lands.

## Validation policy

- Malformed JSON → error, record rejected.
- Missing required fields → error, record rejected.
- Invalid CWE/OWASP → warning (or error in `--strict` for schema issues).
- Secrets in evidence → redacted.
