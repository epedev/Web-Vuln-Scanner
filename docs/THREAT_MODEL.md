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

1. Injection: XSS, SQLi, command injection
2. Broken access control / IDOR
3. CSRF candidates on state-changing forms
4. Security misconfiguration (headers, cookies)
5. Open redirect candidates

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
