# Troubleshooting

## `ModuleNotFoundError: scanner`

Install from repository root (`pip install -e .`) or ensure `xss_module` is on `PYTHONPATH`. The CLI calls `vulnsight.paths.ensure_module_paths()`.

## Scope errors on scan

Default lab mode rejects non-loopback hosts. For authorized external tests only:

```bash
vulnsight scan --target https://authorized.example --allow-external ...
```

## Lab not detecting SQLi / IDOR

1. Confirm lab is the team `target_app`, not the XSS-only fixture.
2. Reseed: `python target_app/seed_data.py`
3. Verify `/login` returns “Invalid credentials” for bad passwords.

## XSS finds nothing

Ensure recon produced pages with parameters (`reports/crawl_map.json`).

## Partial module failures

`vulnsight scan` prints per-module status (`completed`, `failed`, `skipped`). Exit code `1` means at least one enabled module failed; findings from successful modules are still written.
