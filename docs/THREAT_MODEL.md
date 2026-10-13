# Threat model

## Assets

- Operator workstation and credentials used for authorized testing
- Target application data and session integrity (lab/authorized systems only)
- Integrity of VulnSight reports used for academic evaluation

## Actors

| Actor | Motivation |
|-------|------------|
| Authorized student/operator | Assess lab app and produce honest findings |
| Malicious third party | Abuse scanner against unauthorized systems (out of policy) |
| Lab application attacker model | Classic web attacker via browser/network to local app |

## In-scope threats (detection goals)

Mapped primarily to OWASP Top 10:2021 (see `docs/OWASP_TOP10.md`):

1. Injection: XSS, SQLi, command injection (A03)
2. Broken access control / IDOR, CSRF candidates, open redirect (A01)
3. Cryptographic / transport hygiene: cleartext login, HSTS (A02)
4. Security misconfiguration and tech disclosure signals (A05 / A06)
5. Weak session cookie attributes (A07)
6. SSRF candidates on URL-fetch parameters (A10)

## Out-of-scope threats

- Supply-chain compromise of Python packages
- Physical access to the operator machine
- Zero-day browser engine bugs
- Full adversarial red-team of production internet hosts

## Trust boundaries

```text
Operator CLI  --authorized project-->  Local target origin
     |                                        |
     +---- crawl_map / findings JSON ---------+
     |
     v
Reporting artifacts (HTML/MD/PDF/JSON)
```

Crawler discovery does **not** expand authorization beyond the project/target scope.

## False positives / false negatives

| Area | False positive risk | False negative risk |
|------|---------------------|---------------------|
| XSS marker reflection | Encoded/inert reflections may still be candidates | Complex DOM sinks may be missed |
| SQLi auth bypass | Custom login UX may not match heuristics | Non-login SQLi sinks may be missed |
| CSRF form inspection | Header-based CSRF may look tokenless | JS-only forms may be invisible to crawler |
| Security headers | CDN may add headers on other routes | Headers on non-home routes only |
| Access control | Public profiles may look like IDOR | Hidden privileged APIs not linked |

## Residual risk statement

Absence of findings is not certification of security. VulnSight is an educational authorized scanner with bounded detectors and explicit limitations recorded in each report.
