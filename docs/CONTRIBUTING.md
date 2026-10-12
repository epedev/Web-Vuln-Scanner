# Contributing

1. Keep member module ownership clear; prefer extending public APIs (`run_*_module`, `check_local_target`) over rewriting.
2. Do not weaken scope checks to make tests pass.
3. Add unit tests for schema/scope changes. Live lab tests should use `VULNSIGHT_LAB_URL` and must not require a bundled vulnerable app.
4. Never commit secrets, generated reports, or `.venv`.
5. Run `pytest` and `vulnsight doctor` before opening a PR.

See also root [CONTRIBUTING.md](../CONTRIBUTING.md).
