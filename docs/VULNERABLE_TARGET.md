# Vulnerable target (`target_app`)

Educational Flask lab with planted vulnerabilities and secure negative controls.

## Start / stop

```bash
python target_app/app.py
# http://127.0.0.1:5001
# Ctrl+C to stop
```

Environment: `VULNSIGHT_LAB_HOST` (default `127.0.0.1`), `VULNSIGHT_LAB_PORT` (default `5001`).

## Seeded users

| id | username | password | admin |
|----|----------|----------|-------|
| 1 | alice | alice123 | no |
| 2 | bob | bobpass | no |
| 3 | admin | adminpass | yes |

## Planted scenarios

| Vulnerability | Path | Secure counterpart |
|---------------|------|--------------------|
| Reflected XSS | `/reflect?q=` | `/encoded?q=` |
| Stored XSS | `POST /comment` → `/comments` | (encode before store/render) |
| SQLi auth bypass | `POST /login` | `/login-secure` |
| Cmd injection (simulated) | `POST /ping` | validate host; no shell |
| IDOR | `/profile/<id>` | `/profile-secure/<id>` |
| Broken AC | `/admin` | `/admin-secure` |

Command injection is **simulated**: the app looks for `; printf TOKEN` and echoes `TOKEN` without invoking a shell.

## Demonstration checklist (graduation)

1. Start lab; open home page.
2. Show `/reflect?q=<script>…` vs `/encoded`.
3. Post a comment; show raw render on `/comments`.
4. Login bypass with `admin' -- ` on `/login`; show failure on `/login-secure`.
5. Ping with `; printf REDOPS_CMD_TEST`; show marker.
6. Login as alice; open `/profile/2` and `/admin`; contrast secure routes.
7. Run `vulnsight scan` and walk the HTML report remediations.
