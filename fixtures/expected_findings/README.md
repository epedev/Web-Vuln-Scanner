# Expected findings (operator reference)

VulnSight does not ship a vulnerable target. Expected findings depend on the prepared local website you authorize.

When your lab plants the usual graduation scenarios, a full `vulnsight scan` may report classes such as:

| Class | Typical signal |
|-------|----------------|
| Reflected / stored XSS | `xss.reflected` / `xss.stored` |
| SQL injection | auth bypass or error-based evidence |
| Command injection | marker / behavior defined by your lab |
| IDOR | unauthorized object access |
| Broken access control | privileged route reachable without role |

Negative controls on your lab should not produce equivalent confirmed findings.
