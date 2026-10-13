# Changelog

## 0.2.0 — Academic hardening features

- Add `misconfig_module` (security headers, cookie flags, CSRF form candidates, open redirect)
- Add `vulnsight compare` for secure-vs-vulnerable baseline demos
- Add `docs/THREAT_MODEL.md` and assessment-quality section in HTML reports
- Include false-positive / residual-risk guidance in report limitations

## 0.1.8 — Submission presentation

- Classic README, AUTHORS, and project summary for academic submission
- Pull-request template and submission docs
- Cleaner documentation landing page tone

## 0.1.7 — PDF + Markdown report downloads

- Write `vulnsight_report.md` and `vulnsight_report.pdf` by default with scans
- HTML report includes Download buttons for PDF, Markdown, and JSON
- PDF backends: WeasyPrint (package/CLI) with ReportLab fallback
- Missing PDF tools no longer mark the whole assessment incomplete

## 0.1.6 — Crawl-map detection for BYO vulnerable labs

- SQLi, command injection, and access control now use crawl-map discovery instead of only the removed training-lab routes
- Flexible login SQLi bypass signals + unauthenticated IDOR/BAC fallbacks
- Report filter shows "N of M" and matches severity/search more reliably
- Document expected BYO lab signals in docs/VULNERABLE_TARGET.md

## 0.1.5 — Interactive docs + polished report UI

- Add interactive `docs/index.html` showcase with command recipes
- Add `vulnsight docs` to open the landing page
- Upgrade HTML reports with sticky nav, severity chips, and search filtering
- Refresh README visual presentation

## 0.1.4 — No bundled vulnerable target

- Remove `target_app/` and mock XSS fixture apps from the repository
- Scanner expects an operator-provided authorized local website via `--project` / `--target`
- Live integration tests are optional behind `VULNSIGHT_LAB_URL`

## 0.1.1 — Graduation polish

- Clarify simulated command-injection findings (no OS shell claim; probable + lab_simulation evidence)
- Mark partial scans incomplete when modules fail/skip; include access_control in known modules
- Improve CLI scan summary (scope, confirmed vs suspected, actionable errors)
- Allow `::1` loopback; add `POST /_lab/reset` for deterministic demos
- Add negative-control integration tests, demo runbook, architecture diagram
- Align `requirements.txt` with optional `lxml`

## 0.1.0 — VulnSight integrated release

- Add `vulnsight` CLI (`doctor`, `validate-input`, `scan`, `report`, `version`)
- Add unified `target_app` Flask lab covering XSS, SQLi, simulated command injection, IDOR, and broken access control with secure negative controls
- Orchestrate Crawler, XSS, SQLi, command injection, access control, and reporting modules
- Fix access-control / SQLi imports to use shared `scanner.models`
- Add packaging via `pyproject.toml`, docs under `docs/`, and integration tests
