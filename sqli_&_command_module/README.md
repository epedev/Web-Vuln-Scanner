# SQL Injection & Command Injection Module

A modular Python contribution to the Web-Vuln-Scanner project, focused on detecting SQL injection and operating-system command injection in an intentionally vulnerable local Flask training application.

## Modules

* **SQL Injection (`sqli/`)** — checks for authentication-bypass behavior and database error signatures.
* **Command Injection (`command_injection/`)** — checks whether a harmless unique marker supplied through the local application's `host` parameter appears in the HTTP response.
* **Tests (`tests/`)** — automated tests for detection behavior and rejection of non-local targets.
* **Documentation (`docs/`)** — vulnerability descriptions, detection logic, limitations, and remediation guidance.

## Requirements

* Python 3.10 or newer
* `requests`
* `pytest` for tests
* The intentionally vulnerable Flask training application for live local checks

The modules currently reuse the shared finding schema from `xss_module/scanner/models.py`. They are organized separately, but are not yet integrated into the main CLI.

## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r 'sqli_&_command_module/requirements.txt'
```

## Run tests

```bash
python -m pytest -q 'sqli_&_command_module/tests/'
```

## Run the local checks

Start the intentionally vulnerable Flask training app on `127.0.0.1:5000`, then run these commands from the repository root:

```bash
PYTHONPATH=".:sqli_&_command_module" python -c \
'from sqli.detector import check_local_target; print(check_local_target("http://127.0.0.1:5000").to_dict())'

PYTHONPATH=".:sqli_&_command_module" python -c \
'from command_injection.detector import check_local_target; print(check_local_target("http://127.0.0.1:5000").to_dict())'
```

Only run active checks against the intentionally vulnerable local lab or another explicitly authorized target.

## Limitations

* Detection behavior is tailored to the documented training application.
* Database error signatures are indicators, not proof of exploitability.
* A command-output marker is evidence of the tested behavior, not a guarantee that every command-injection vulnerability can be detected.
* Main CLI integration and compatibility with arbitrary applications are future work.

## Remediation

* **SQL injection:** use parameterized queries and securely handle passwords.
* **Command injection:** avoid shell execution, pass arguments as a list with `shell=False`, and validate input.

## Project status

Initial standalone module organization and unit tests. CLI integration is intentionally deferred.
