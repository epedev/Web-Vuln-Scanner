# Changelog

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
