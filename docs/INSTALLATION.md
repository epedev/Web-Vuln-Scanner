# Installation

## Requirements

- Python **3.10+**
- Linux, macOS, or Windows with a working Python toolchain
- Network access only for installing packages (scans default to loopback)

## Linux / macOS

```bash
git clone https://github.com/epedev/Web-Vuln-Scanner.git
cd Web-Vuln-Scanner

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

vulnsight --help
vulnsight doctor
```

## Windows (PowerShell)

```powershell
git clone https://github.com/epedev/Web-Vuln-Scanner.git
cd Web-Vuln-Scanner

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

vulnsight --help
vulnsight doctor
```

## Optional extras

```bash
# Browser-based XSS confirmation (Playwright)
python -m pip install -e ".[browser]"
playwright install chromium

# PDF reports (WeasyPrint + system libraries)
python -m pip install -e ".[pdf]"
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `vulnsight: command not found` | Activate the venv; re-run `pip install -e .` |
| Import errors for `scanner.models` | Install from repo root with `pip install -e .` so paths resolve |
| `doctor` reports missing Flask/requests | `pip install -e ".[dev]"` |
| Lab port in use | `VULNSIGHT_LAB_PORT=5002 python target_app/app.py` |

See also [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and [SECURITY.md](SECURITY.md).
