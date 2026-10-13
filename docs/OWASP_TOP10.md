# OWASP Top 10:2021 mapping

VulnSight maps findings to the [OWASP Top 10:2021](https://owasp.org/Top10/) categories and includes a coverage table in HTML and Markdown reports (`summary.owasp_top10`).

Zero findings in a category means no matching detector output for the scanned scope — **not** that the category is safe.

| ID | Category | VulnSight coverage |
|----|----------|--------------------|
| A01:2021 | Broken Access Control | IDOR / broken access control, CSRF candidates, open redirect |
| A02:2021 | Cryptographic Failures | Cleartext HTTP login/password forms; missing HSTS on HTTPS |
| A03:2021 | Injection | XSS, SQL injection, OS command injection |
| A04:2021 | Insecure Design | Not dynamically tested; noted in threat model |
| A05:2021 | Security Misconfiguration | Missing security headers, cookie hygiene overlap |
| A06:2021 | Vulnerable and Outdated Components | Technology disclosure (`Server`, `X-Powered-By`, …) — signal only |
| A07:2021 | Identification and Authentication Failures | Weak cookie attributes (HttpOnly / SameSite / Secure) |
| A08:2021 | Software and Data Integrity Failures | Limited / no primary detector |
| A09:2021 | Security Logging and Monitoring Failures | Not externally verifiable by this scanner |
| A10:2021 | Server-Side Request Forgery (SSRF) | Candidate probes on URL-fetch style parameters |

## Report artifacts

- HTML section: **OWASP Top 10:2021 coverage**
- Markdown section: same table
- JSON summary field: `summary.owasp_top10`

## Honesty constraints

- SSRF findings are **candidate**-level unless stronger evidence is present.
- A06 disclosure findings fingerprint stack exposure; they do not prove a known CVE.
- A04 / A08 / A09 are marked `limited_coverage` when empty so reports do not imply full Top 10 testing.
