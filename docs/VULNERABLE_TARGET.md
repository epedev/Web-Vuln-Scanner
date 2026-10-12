# Vulnerable target

VulnSight does **not** ship a deliberately vulnerable web application.

Bring your own authorized local target and point the scanner at it:

```bash
vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT
vulnsight scan --project myproject.json
```

## What the detectors look for

Modules use the crawl map from recon **and** common lab routes:

| Module | Discovery | Signals that produce findings |
|--------|-----------|-------------------------------|
| XSS | Crawl map params/forms | Marker reflection / stored sinks |
| SQLi | `/login` + crawl forms/params | Auth bypass behavior **or** SQL error signatures in responses |
| Command injection | `/ping` + host/cmd-like params | Unique output marker echoed back |
| Access control | `/profile/{id}`, `/admin` (+ crawl discovery) | Cross-user or unauthenticated access returns HTTP 200 |

Tips for teammate labs:

1. Link injectable pages from the home page so the crawler can find them.
2. Prefer loopback (`127.0.0.1` / `localhost`).
3. If login uses different field names, expose them in HTML forms — SQLi will probe crawl-discovered forms.
4. Open `reports/findings_raw.json` after a scan to see per-module counts and errors.

Detection modules that call `check_local_target()` still require loopback HTTP(S) targets by default.
