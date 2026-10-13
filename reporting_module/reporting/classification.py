"""CWE and OWASP Top 10 2021 classification validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

CWE_RE = re.compile(r"^CWE-(\d{1,5})$", re.IGNORECASE)

# OWASP Top 10 2021 canonical labels (workbook baseline)
OWASP_2021 = {
    "A01:2021-Broken Access Control": "A01:2021",
    "A02:2021-Cryptographic Failures": "A02:2021",
    "A03:2021-Injection": "A03:2021",
    "A04:2021-Insecure Design": "A04:2021",
    "A05:2021-Security Misconfiguration": "A05:2021",
    "A06:2021-Vulnerable and Outdated Components": "A06:2021",
    "A07:2021-Identification and Authentication Failures": "A07:2021",
    "A08:2021-Software and Data Integrity Failures": "A08:2021",
    "A09:2021-Security Logging and Monitoring Failures": "A09:2021",
    "A10:2021-Server-Side Request Forgery": "A10:2021",
}

OWASP_ALIASES = {
    "a03:2021-injection": "A03:2021-Injection",
    "a03:2021": "A03:2021-Injection",
    "a03 injection": "A03:2021-Injection",
    "injection": "A03:2021-Injection",
    "a05:2021-security misconfiguration": "A05:2021-Security Misconfiguration",
    "a05:2021": "A05:2021-Security Misconfiguration",
    "security misconfiguration": "A05:2021-Security Misconfiguration",
    "a01:2021": "A01:2021-Broken Access Control",
    "a02:2021": "A02:2021-Cryptographic Failures",
    "a04:2021": "A04:2021-Insecure Design",
    "a06:2021": "A06:2021-Vulnerable and Outdated Components",
    "a07:2021": "A07:2021-Identification and Authentication Failures",
    "a08:2021": "A08:2021-Software and Data Integrity Failures",
    "a09:2021": "A09:2021-Security Logging and Monitoring Failures",
    "a10:2021": "A10:2021-Server-Side Request Forgery",
    "a10:2021-server-side request forgery (ssrf)": "A10:2021-Server-Side Request Forgery",
    "ssrf": "A10:2021-Server-Side Request Forgery",
}

# Common CWEs used by this project — offline allowlist, not live MITRE sync.
KNOWN_CWES = {
    "CWE-79",  # XSS
    "CWE-89",  # SQLi
    "CWE-78",  # OS command injection
    "CWE-16",  # Configuration
    "CWE-693",  # Protection Mechanism Failure
    "CWE-1021",  # Improper Restriction of Rendered UI Layers
    "CWE-200",  # Exposure of Sensitive Information
    "CWE-358",  # Improperly Implemented Security Check
    "CWE-614",  # Sensitive Cookie without Secure
    "CWE-942",  # Permissive Cross-domain Policy
    "CWE-319",  # Cleartext Transmission of Sensitive Information
    "CWE-352",  # CSRF
    "CWE-601",  # Open Redirect
    "CWE-918",  # SSRF
    "CWE-639",  # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-284",  # Improper Access Control
}


@dataclass
class ClassificationResult:
    cwe: str | None
    owasp: str | None
    warnings: list[str]
    errors: list[str]


def normalize_cwe(value: str | None) -> tuple[str | None, list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    if value is None or str(value).strip() == "":
        return None, ["missing CWE"], []
    raw = str(value).strip()
    match = CWE_RE.match(raw)
    if not match:
        # allow bare numbers
        if raw.isdigit():
            normalized = f"CWE-{int(raw)}"
        else:
            errors.append(f"invalid CWE syntax: {raw}")
            return None, warnings, errors
    else:
        normalized = f"CWE-{int(match.group(1))}"
    if normalized not in KNOWN_CWES:
        warnings.append(
            f"{normalized} not in offline project allowlist (accepted with warning)"
        )
    return normalized, warnings, errors


def normalize_owasp(value: str | None) -> tuple[str | None, list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    if value is None or str(value).strip() == "":
        return None, ["missing OWASP category"], []
    raw = str(value).strip()
    if raw in OWASP_2021:
        return raw, warnings, errors
    alias = OWASP_ALIASES.get(raw.lower())
    if alias:
        return alias, warnings, errors
    # Try prefix match A0X:2021
    for full in OWASP_2021:
        if raw.upper().startswith(OWASP_2021[full]):
            return full, warnings, errors
    errors.append(f"unsupported OWASP Top 10 2021 category: {raw}")
    return None, warnings, errors


def validate_classification(
    cwe: str | None,
    owasp: str | None,
    vulnerability_type: str | None = None,
) -> ClassificationResult:
    cwe_n, cwe_w, cwe_e = normalize_cwe(cwe)
    owasp_n, owasp_w, owasp_e = normalize_owasp(owasp)
    warnings = cwe_w + owasp_w
    errors = cwe_e + owasp_e

    vtype = (vulnerability_type or "").lower()
    if cwe_n == "CWE-79" and owasp_n and not owasp_n.startswith("A03"):
        warnings.append("CWE-79 usually maps to OWASP A03:2021 Injection")
    if cwe_n == "CWE-89" and owasp_n and not owasp_n.startswith("A03"):
        warnings.append("CWE-89 usually maps to OWASP A03:2021 Injection")
    # Hygiene module emits several legitimate Top 10 mappings beyond A05.
    allowed_misconfig_owasp = ("A01", "A02", "A05", "A06", "A07", "A10")
    if (
        "misconfig" in vtype
        and owasp_n
        and not any(owasp_n.startswith(prefix) for prefix in allowed_misconfig_owasp)
    ):
        warnings.append(
            "Misconfiguration findings commonly map to OWASP A05:2021 "
            "(or A01/A02/A06/A07/A10 for related hygiene checks)"
        )
    return ClassificationResult(
        cwe=cwe_n, owasp=owasp_n, warnings=warnings, errors=errors
    )


def default_classification(vulnerability_type: str) -> tuple[str | None, str | None]:
    v = vulnerability_type.lower()
    if "xss" in v or "cross-site" in v:
        return "CWE-79", "A03:2021-Injection"
    if "sql" in v:
        return "CWE-89", "A03:2021-Injection"
    if "command" in v:
        return "CWE-78", "A03:2021-Injection"
    if "ssrf" in v or "server-side request" in v:
        return "CWE-918", "A10:2021-Server-Side Request Forgery"
    if "csrf" in v:
        return "CWE-352", "A01:2021-Broken Access Control"
    if "open redirect" in v:
        return "CWE-601", "A01:2021-Broken Access Control"
    if "cryptographic" in v or "cleartext" in v:
        return "CWE-319", "A02:2021-Cryptographic Failures"
    if "misconfig" in v or "header" in v:
        return "CWE-693", "A05:2021-Security Misconfiguration"
    return None, None
