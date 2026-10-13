
"""OWASP Top 10:2021 catalog and coverage summary for VulnSight reports."""

from __future__ import annotations

from typing import Any, Iterable

from reporting.schema import CanonicalFinding

OWASP_TOP_10_2021: list[dict[str, str]] = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "full": "A01:2021-Broken Access Control",
        "vulnsight_coverage": "IDOR, broken access control, CSRF candidates, open redirect",
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "full": "A02:2021-Cryptographic Failures",
        "vulnsight_coverage": "Cleartext HTTP session/cookie risks; HSTS absence on HTTPS",
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "full": "A03:2021-Injection",
        "vulnsight_coverage": "XSS, SQL injection, OS command injection",
    },
    {
        "id": "A04:2021",
        "name": "Insecure Design",
        "full": "A04:2021-Insecure Design",
        "vulnsight_coverage": "Not dynamically tested (design-time); noted in threat model",
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "full": "A05:2021-Security Misconfiguration",
        "vulnsight_coverage": "Security headers, verbose server headers, cookie flags",
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "full": "A06:2021-Vulnerable and Outdated Components",
        "vulnsight_coverage": "Technology disclosure via Server / X-Powered-By (signal only)",
    },
    {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "full": "A07:2021-Identification and Authentication Failures",
        "vulnsight_coverage": "Weak cookie attributes; cleartext login transport on HTTP labs",
    },
    {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "full": "A08:2021-Software and Data Integrity Failures",
        "vulnsight_coverage": "Limited dynamic coverage (not a primary detector)",
    },
    {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "full": "A09:2021-Security Logging and Monitoring Failures",
        "vulnsight_coverage": "Not externally verifiable in this scanner",
    },
    {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery",
        "full": "A10:2021-Server-Side Request Forgery (SSRF)",
        "vulnsight_coverage": "SSRF candidates on URL-fetch style parameters",
    },
]


def _category_key(owasp: str | None) -> str | None:
    if not owasp:
        return None
    text = owasp.strip().upper()
    for item in OWASP_TOP_10_2021:
        if text.startswith(item["id"]) or item["full"].upper() in text or text.startswith(item["full"].upper()):
            return item["id"]
    # loose A0X match
    for item in OWASP_TOP_10_2021:
        if item["id"].split(":")[0] in text.replace(" ", ""):
            return item["id"]
    return None


def build_owasp_coverage(findings: Iterable[CanonicalFinding]) -> dict[str, Any]:
    counts = {item["id"]: 0 for item in OWASP_TOP_10_2021}
    for f in findings:
        key = _category_key(f.owasp)
        if key:
            counts[key] += 1

    rows = []
    tested = 0
    for item in OWASP_TOP_10_2021:
        count = counts[item["id"]]
        status = "findings" if count else "no_findings_in_scope"
        # Categories with little/no dynamic testing
        if item["id"] in {"A04:2021", "A08:2021", "A09:2021"} and count == 0:
            status = "limited_coverage"
        else:
            tested += 1
        rows.append(
            {
                "id": item["id"],
                "name": item["name"],
                "full": item["full"],
                "findings": count,
                "status": status,
                "vulnsight_coverage": item["vulnsight_coverage"],
            }
        )

    with_findings = sum(1 for r in rows if r["findings"] > 0)
    return {
        "standard": "OWASP Top 10:2021",
        "categories": rows,
        "categories_with_findings": with_findings,
        "categories_tracked": len(rows),
        "note": (
            "Coverage means VulnSight has detectors or explicit mapping for the category; "
            "zero findings is not proof the category is safe."
        ),
    }
