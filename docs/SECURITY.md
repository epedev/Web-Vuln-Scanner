# Security and authorized use

## Scope

VulnSight is an **educational** scanner. Default operation is restricted to the team-authored Flask lab on loopback.

- Do **not** scan third-party systems without written authorization.
- Do **not** treat crawler output as permission to attack those URLs.
- Use `--allow-external` only for explicitly authorized assessments.

## Lab warnings

`target_app` intentionally contains:

- SQL injection, simulated command injection, XSS, IDOR, broken access control

It must:

- Bind to `127.0.0.1` by default
- Never be exposed to the public Internet
- Use only fake seed credentials (`alice`/`bob`/`admin` lab passwords)

## Sensitive data handling

Reports redact common secret patterns. Still avoid pasting real cookies, tokens, or production credentials into crawl maps or findings.

## Responsible disclosure

If you discover a bug in VulnSight itself, follow the root [SECURITY.md](../SECURITY.md) process.
