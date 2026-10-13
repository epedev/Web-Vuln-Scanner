# OWASP Top 10 mapping (2025 primary)

VulnSight primarily maps findings to the current **[OWASP Top 10:2025](https://owasp.org/Top10/2025/)** release (2024–2026 cycle). HTML and Markdown reports include:

- a **2025 coverage table** (`summary.owasp_top10`)
- a **legacy 2021 continuity table** (`summary.owasp_top10.legacy_2021`)

Zero findings in a category means no matching detector output for the scanned scope — **not** that the category is safe.

## OWASP Top 10:2025

| ID | Category | VulnSight coverage |
|----|----------|--------------------|
| A01:2025 | Broken Access Control | IDOR / broken access control, CSRF, open redirect, SSRF candidates |
| A02:2025 | Security Misconfiguration | Missing security headers and related hygiene issues |
| A03:2025 | Software Supply Chain Failures | Technology disclosure (`Server`, `X-Powered-By`) — signal only |
| A04:2025 | Cryptographic Failures | Cleartext HTTP login/password forms; missing HSTS on HTTPS |
| A05:2025 | Injection | XSS, SQL injection, OS command injection |
| A06:2025 | Insecure Design | Not dynamically tested; noted in threat model |
| A07:2025 | Authentication Failures | Weak cookie attributes (HttpOnly / SameSite / Secure) |
| A08:2025 | Software or Data Integrity Failures | Limited / no primary detector |
| A09:2025 | Security Logging and Alerting Failures | Not externally verifiable by this scanner |
| A10:2025 | Mishandling of Exceptional Conditions | Verbose error / stack-trace disclosure probes |

## 2021 → 2025 continuity map

| 2021 | 2025 |
|------|------|
| A01 Broken Access Control | A01 Broken Access Control |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | A02 Security Misconfiguration |
| A06 Vulnerable and Outdated Components | A03 Software Supply Chain Failures (closest signal) |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery (SSRF) | A01 Broken Access Control (SSRF folded into A01 in 2025) |

There is no separate official OWASP Top 10 “2024” or “2026” edition; **2025** is the current standard for this period.

## Honesty constraints

- SSRF findings remain **candidate**-level unless stronger evidence is present.
- A03 disclosure findings fingerprint stack exposure; they do not prove a known CVE.
- A06 / A08 / A09 are marked `limited_coverage` when empty so reports do not imply full Top 10 testing.
- A10 probes look for verbose diagnostics; absence of a stack trace does not prove secure error handling.
