# Changelog

## 0.1.0 — VulnSight integrated release

- Add `vulnsight` CLI (`doctor`, `validate-input`, `scan`, `report`, `version`)
- Add unified `target_app` Flask lab covering XSS, SQLi, simulated command injection, IDOR, and broken access control with secure negative controls
- Orchestrate Crawler, XSS, SQLi, command injection, access control, and reporting modules
- Fix access-control / SQLi imports to use shared `scanner.models`
- Add packaging via `pyproject.toml`, docs under `docs/`, and integration tests
