# Contributing

1. Keep member module ownership clear; prefer extending public APIs (`run_*_module`, `check_local_target`) over rewriting.
2. Do not weaken scope checks to make tests pass.
3. Add unit tests for schema/scope changes and integration tests against `target_app` for new planted vulns.
4. Never commit secrets, `lab.db`, generated reports, or `.venv`.
5. Run `pytest` and `vulnsight doctor` before opening a PR.

See also root [CONTRIBUTING.md](../CONTRIBUTING.md).
