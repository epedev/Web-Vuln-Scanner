# Contributing

Thanks for helping improve VulnSight.

## Workflow

1. Work in a feature branch.
2. Keep changes scoped to one module when possible (`xss_module`, `sqli_&_command_module`, `reporting_module`).
3. Add or update tests with behavior changes.
4. Run the relevant pytest suite before opening a PR.
5. Do not commit secrets, live credentials, or production scan output.

## Module contracts

- Detection modules should emit JSON compatible with `xss_module/scanner/models.py` (`ScanResult` with a `findings` array).
- The reporting module consumes those JSON files via `report_module.py`.
- Document new finding types, CWEs, and limitations in the module docs.

## Authorized testing only

Use lab targets or systems you are explicitly authorized to assess.
