# Modular Web Vulnerability Scanner

Cybersecurity graduation project — authorized / lab-only scanning toolkit.

## Status

The repository started empty. This baseline includes:

- **Recon** (`recon/`) — produces `crawl_map.json` (schema v1.0)
- **XSS module** (`xss/`, entry `xss_module.py`) — reflected + stored detection
- **Main scanner** (`scanner/main.py`) — module orchestration
- **Lab fixture** (`fixtures/vulnerable_app/`) — intentional XSS training target
- **Tests** (`tests/`) — unit + mocked integration coverage

## Quick start

```bash
python -m pip install -r requirements.txt

# Start lab app (loopback only)
python fixtures/vulnerable_app/app.py

# Run XSS module (explicit scope required)
python xss_module.py \
  --crawl-map fixtures/sample_crawl_map.json \
  --origin http://127.0.0.1:5001 \
  --allow-loopback \
  --active-verify --metachar-probes \
  --enable-stored-xss \
  -o findings.json -v

# Tests
pytest -q
```

## Documentation

- [XSS module](docs/XSS_MODULE.md)
- [crawl_map schema](docs/CRAWL_MAP_SCHEMA.md)
- [Lab fixture](fixtures/vulnerable_app/README.md)

## Authorization

Only use against systems you own or are explicitly authorized to test. Scope is fail-closed: crawl-map URLs alone do not authorize testing.
