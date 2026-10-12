# Access Control Module

A modular Python contribution to the Web-Vuln-Scanner project, focused on detecting Insecure Direct Object Reference (IDOR) and broken access control in an intentionally vulnerable local Flask training application.

## Modules

* **Access control (`access_control/`)** — checks for IDOR on user profile resources and broken access control on privileged routes.
* **Tests (`tests/`)** — automated tests for detection behavior and rejection of non-local targets.
* **Documentation (`docs/`)** — vulnerability descriptions, detection logic, limitations, and remediation guidance.

## Requirements

* Python 3.10 or newer
* `requests`
* `pytest` for tests
* The intentionally vulnerable Flask training application for live local checks

The module reuses the shared finding schema from `xss_module/scanner/models.py`, same as the SQLi/command injection module. It is organized separately and not yet integrated into the main CLI.

## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r access_control_module/requirements.txt
```

## Usage

```python
from access_control.detector import check_local_target

result = check_local_target("http://127.0.0.1:5000")
for finding in result.findings:
    print(finding.severity, finding.title)
```

Requires the seed accounts `alice`/`alice123` and `bob`/`bobpass` to exist in the target app's database (see the target app's own `init_db.py`).

## Tests

```bash
cd access_control_module
pytest tests/ -v
```
