# Installation

## Requirements

- Python **3.10+**
- Linux, macOS, or Windows with a working Python toolchain
- Your own authorized local website to scan (not included in this repo)

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
vulnsight docs   # opens interactive docs/index.html
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
python -m pip install -e ".[browser]"
playwright install chromium

python -m pip install -e ".[pdf]"
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `vulnsight: command not found` | Activate the venv; re-run `pip install -e .` |
| Import errors for `scanner.models` | Install from repo root with `pip install -e .` |
| Scan cannot connect | Start your authorized local website first |

See also [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and [SECURITY.md](SECURITY.md).
