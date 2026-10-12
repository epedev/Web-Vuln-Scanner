# Findings schema

## Detection module output (`ScanResult`)

Defined in `xss_module/scanner/models.py`. Every detector returns:

- `module`, `findings[]`, `outcomes[]`, `stats`, `errors`, `limitations`

Each `Finding` includes title, vulnerability_type, url, method, parameter, evidence, confidence, severity, verification_status, CWE/OWASP, remediation, and provenance fields.

## Reporting canonical finding

`reporting_module` normalizes module JSON into `CanonicalFinding` (schema version `1.0`). See `reporting_module/docs/FINDINGS_SCHEMA.md` for field-level detail.

## Severity vs confidence vs verification

| Concept | Meaning |
|---------|---------|
| Severity | Estimated technical impact |
| Confidence | Strength of evidence |
| Verification status | confirmed / probable / candidate / … |

Reflection alone is not confirmed XSS. Identifier changes alone are not confirmed IDOR. SQL errors alone are not confirmed SQLi. CVSS is only recorded when a defensible vector exists; otherwise status is `unscored`.
