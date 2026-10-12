# Troubleshooting

## `ModuleNotFoundError: scanner`

Install from repository root (`pip install -e .`) or ensure `xss_module` is on `PYTHONPATH`. The CLI calls `vulnsight.paths.ensure_module_paths()`.

## Scope errors on scan

Default lab mode rejects non-loopback hosts. For authorized private/local targets use a project file:

```bash
vulnsight init-project -o myproject.json --target http://192.168.1.10:8080
# set allow_private_network true and authorization fields
vulnsight scan --project myproject.json
```

## Connection / empty crawl map

1. Confirm your prepared website is running at the project `target` URL.
2. Confirm the origin matches (`authorized_origins`).
3. Increase `--max-pages` / `--timeout` if the site is slow.

## Partial module failures

`vulnsight scan` prints per-module status (`completed`, `failed`, `skipped`). Exit code `1` means at least one enabled module failed; findings from successful modules are still written.
