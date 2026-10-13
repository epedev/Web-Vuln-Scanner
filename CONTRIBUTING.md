# Contributing

Thank you for contributing to VulnSight.

## Guidelines

1. Prefer a focused feature branch for each change.
2. Keep module ownership clear (`Crawler/`, `xss_module/`, `sqli_&_command_module/`, `access_control_module/`, `reporting_module/`).
3. Add or update tests when behavior changes.
4. Run `python -m pytest` before opening a pull request.
5. Do not commit secrets, credentials, or live scan reports (`reports/` is gitignored).

## Contracts

- Detection modules emit JSON compatible with `xss_module/scanner/models.py`.
- The reporting module consumes findings through `report_module.py`.
- Document new finding types and limitations in the relevant module docs.

## Authorized testing

Only test systems you own or are explicitly authorized to assess.
