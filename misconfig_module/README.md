# Misconfiguration / Security Hygiene Module

Checks authorized local targets for:

- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)
- Weak session-cookie attributes (HttpOnly / Secure / SameSite)
- State-changing forms without CSRF tokens
- Open-redirect candidates on common redirect parameters

## API

```python
from misconfig.detector import check_local_target
result = check_local_target("http://127.0.0.1:5000", crawl_map=crawl_map)
```
