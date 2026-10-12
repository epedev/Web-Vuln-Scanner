# Vulnerable target

VulnSight does **not** ship a deliberately vulnerable web application.

Bring your own authorized local target (for example a class DVWA/Juice Shop instance, or your team's prepared vulnerable site) and point the scanner at it with an authorization project file:

```bash
vulnsight init-project -o myproject.json --target http://127.0.0.1:PORT
vulnsight scan --project myproject.json
```

Detection modules that call `check_local_target()` expect loopback HTTP targets by default. Document your lab's endpoints and credentials in your own project notes — do not commit real production secrets.
