"""OWASP Top 10 catalogs and coverage summaries for VulnSight reports.

Primary standard: OWASP Top 10:2025 (current release for the 2024–2026 cycle).
Legacy OWASP Top 10:2021 is retained for continuity and dual coverage tables.
See https://owasp.org/Top10/2025/
"""

from __future__ import annotations

from typing import Any, Iterable

from reporting.schema import CanonicalFinding

OWASP_TOP_10_2025: list[dict[str, str]] = [
    {
        "id": "A01:2025",
        "name": "Broken Access Control",
        "full": "A01:2025-Broken Access Control",
        "vulnsight_coverage": "IDOR, broken access control, CSRF, open redirect, SSRF candidates",
    },
    {
        "id": "A02:2025",
        "name": "Security Misconfiguration",
        "full": "A02:2025-Security Misconfiguration",
        "vulnsight_coverage": "Missing security headers and related hygiene misconfigurations",
    },
    {
        "id": "A03:2025",
        "name": "Software Supply Chain Failures",
        "full": "A03:2025-Software Supply Chain Failures",
        "vulnsight_coverage": "Technology disclosure via Server / X-Powered-By (signal only)",
    },
    {
        "id": "A04:2025",
        "name": "Cryptographic Failures",
        "full": "A04:2025-Cryptographic Failures",
        "vulnsight_coverage": "Cleartext HTTP login/password forms; missing HSTS on HTTPS",
    },
    {
        "id": "A05:2025",
        "name": "Injection",
        "full": "A05:2025-Injection",
        "vulnsight_coverage": "XSS, SQL injection, OS command injection",
    },
    {
        "id": "A06:2025",
        "name": "Insecure Design",
        "full": "A06:2025-Insecure Design",
        "vulnsight_coverage": "Not dynamically tested (design-time); noted in threat model",
    },
    {
        "id": "A07:2025",
        "name": "Authentication Failures",
        "full": "A07:2025-Authentication Failures",
        "vulnsight_coverage": "Weak session cookie attributes (HttpOnly / SameSite / Secure)",
    },
    {
        "id": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "full": "A08:2025-Software or Data Integrity Failures",
        "vulnsight_coverage": "Limited dynamic coverage (not a primary detector)",
    },
    {
        "id": "A09:2025",
        "name": "Security Logging and Alerting Failures",
        "full": "A09:2025-Security Logging and Alerting Failures",
        "vulnsight_coverage": "Not externally verifiable in this scanner",
    },
    {
        "id": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "full": "A10:2025-Mishandling of Exceptional Conditions",
        "vulnsight_coverage": "Verbose error / stack-trace disclosure probes",
    },
]

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
        "vulnsight_coverage": "SSRF candidates on URL-fetch style parameters (mapped to A01:2025)",
    },
]

# Official continuity map from Top 10:2021 → Top 10:2025 category IDs.
MAP_2021_TO_2025: dict[str, str] = {
    "A01:2021": "A01:2025",
    "A02:2021": "A04:2025",
    "A03:2021": "A05:2025",
    "A04:2021": "A06:2025",
    "A05:2021": "A02:2025",
    "A06:2021": "A03:2025",
    "A07:2021": "A07:2025",
    "A08:2021": "A08:2025",
    "A09:2021": "A09:2025",
    "A10:2021": "A01:2025",  # SSRF folded into Broken Access Control in 2025
}

LIMITED_2025 = {"A06:2025", "A08:2025", "A09:2025"}
LIMITED_2021 = {"A04:2021", "A08:2021", "A09:2021"}


def _match_catalog(text: str, catalog: list[dict[str, str]]) -> str | None:
    import re

    upper = text.strip().upper()
    compact = upper.replace(" ", "")
    for item in catalog:
        if (
            upper.startswith(item["id"])
            or item["full"].upper() in upper
            or upper.startswith(item["full"].upper())
        ):
            return item["id"]
    # Avoid cross-year false hits (e.g. A05:2025 matching A05:2021).
    year_hit = re.search(r":(20\d{2})", upper)
    catalog_year = catalog[0]["id"].split(":")[1] if catalog else None
    if year_hit and catalog_year and year_hit.group(1) != catalog_year:
        return None
    for item in catalog:
        prefix = item["id"].split(":")[0]
        if prefix in compact:
            return item["id"]
    return None


def category_key_2025(owasp: str | None) -> str | None:
    """Resolve a finding OWASP label to an OWASP Top 10:2025 category id."""
    if not owasp:
        return None
    text = owasp.strip()
    direct = _match_catalog(text, OWASP_TOP_10_2025)
    if direct:
        return direct
    legacy = _match_catalog(text, OWASP_TOP_10_2021)
    if legacy:
        return MAP_2021_TO_2025.get(legacy)
    return None


def category_key_2021(owasp: str | None) -> str | None:
    """Resolve a finding OWASP label to an OWASP Top 10:2021 category id."""
    if not owasp:
        return None
    text = owasp.strip()
    direct = _match_catalog(text, OWASP_TOP_10_2021)
    if direct:
        return direct
    # Reverse-map from 2025 labels where unambiguous.
    key_2025 = _match_catalog(text, OWASP_TOP_10_2025)
    if not key_2025:
        return None
    reverse = {
        "A01:2025": "A01:2021",
        "A02:2025": "A05:2021",
        "A03:2025": "A06:2021",
        "A04:2025": "A02:2021",
        "A05:2025": "A03:2021",
        "A06:2025": "A04:2021",
        "A07:2025": "A07:2021",
        "A08:2025": "A08:2021",
        "A09:2025": "A09:2021",
        # A10:2025 has no direct 2021 peer; leave unmapped.
    }
    return reverse.get(key_2025)


def _build_rows(
    catalog: list[dict[str, str]],
    counts: dict[str, int],
    limited: set[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in catalog:
        count = counts[item["id"]]
        status = "findings" if count else "no_findings_in_scope"
        if item["id"] in limited and count == 0:
            status = "limited_coverage"
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
    return rows


def build_owasp_coverage(findings: Iterable[CanonicalFinding]) -> dict[str, Any]:
    """Build primary OWASP Top 10:2025 coverage plus legacy 2021 continuity table."""
    findings_list = list(findings)
    counts_2025 = {item["id"]: 0 for item in OWASP_TOP_10_2025}
    counts_2021 = {item["id"]: 0 for item in OWASP_TOP_10_2021}

    for f in findings_list:
        key_2025 = category_key_2025(f.owasp)
        if key_2025:
            counts_2025[key_2025] += 1
        key_2021 = category_key_2021(f.owasp)
        if key_2021:
            counts_2021[key_2021] += 1

    rows_2025 = _build_rows(OWASP_TOP_10_2025, counts_2025, LIMITED_2025)
    rows_2021 = _build_rows(OWASP_TOP_10_2021, counts_2021, LIMITED_2021)

    return {
        "standard": "OWASP Top 10:2025",
        "edition_window": "2024–2026",
        "categories": rows_2025,
        "categories_with_findings": sum(1 for r in rows_2025 if r["findings"] > 0),
        "categories_tracked": len(rows_2025),
        "note": (
            "Primary mapping uses OWASP Top 10:2025 (current release for the 2024–2026 cycle). "
            "Coverage means VulnSight has detectors or explicit mapping for the category; "
            "zero findings is not proof the category is safe."
        ),
        "legacy_2021": {
            "standard": "OWASP Top 10:2021",
            "categories": rows_2021,
            "categories_with_findings": sum(1 for r in rows_2021 if r["findings"] > 0),
            "categories_tracked": len(rows_2021),
            "note": (
                "Legacy 2021 continuity table. SSRF (A10:2021) maps into A01:2025; "
                "component disclosure maps toward A03:2025 supply-chain signals."
            ),
        },
        "map_2021_to_2025": dict(MAP_2021_TO_2025),
    }


# Back-compat alias used by older imports/tests.
def _category_key(owasp: str | None) -> str | None:
    return category_key_2025(owasp)
