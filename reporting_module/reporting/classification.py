"""CWE and OWASP Top 10 classification validation.

Primary standard: OWASP Top 10:2025. Legacy Top 10:2021 labels are accepted and
normalized to the 2025 equivalents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from reporting.owasp_top10 import MAP_2021_TO_2025, OWASP_TOP_10_2021, OWASP_TOP_10_2025

CWE_RE = re.compile(r"^CWE-(\d{1,5})$", re.IGNORECASE)

OWASP_2025 = {item["full"]: item["id"] for item in OWASP_TOP_10_2025}
OWASP_2021 = {item["full"]: item["id"] for item in OWASP_TOP_10_2021}
# Prefer the non-(SSRF) full label for A10:2021 canonicalization before remap.
OWASP_2021["A10:2021-Server-Side Request Forgery"] = "A10:2021"

FULL_BY_ID_2025 = {item["id"]: item["full"] for item in OWASP_TOP_10_2025}
FULL_BY_ID_2021 = {item["id"]: item["full"] for item in OWASP_TOP_10_2021}

OWASP_ALIASES = {
    # Generic / short forms → 2025
    "injection": "A05:2025-Injection",
    "a05 injection": "A05:2025-Injection",
    "a05:2025": "A05:2025-Injection",
    "a05:2025-injection": "A05:2025-Injection",
    "security misconfiguration": "A02:2025-Security Misconfiguration",
    "a02:2025": "A02:2025-Security Misconfiguration",
    "a01:2025": "A01:2025-Broken Access Control",
    "a03:2025": "A03:2025-Software Supply Chain Failures",
    "a04:2025": "A04:2025-Cryptographic Failures",
    "a06:2025": "A06:2025-Insecure Design",
    "a07:2025": "A07:2025-Authentication Failures",
    "a08:2025": "A08:2025-Software or Data Integrity Failures",
    "a09:2025": "A09:2025-Security Logging and Alerting Failures",
    "a10:2025": "A10:2025-Mishandling of Exceptional Conditions",
    "ssrf": "A01:2025-Broken Access Control",
    "authentication failures": "A07:2025-Authentication Failures",
    # Legacy 2021 short forms (normalized to 2025 via MAP)
    "a03:2021-injection": "A03:2021-Injection",
    "a03:2021": "A03:2021-Injection",
    "a03 injection": "A03:2021-Injection",
    "a05:2021-security misconfiguration": "A05:2021-Security Misconfiguration",
    "a05:2021": "A05:2021-Security Misconfiguration",
    "a01:2021": "A01:2021-Broken Access Control",
    "a02:2021": "A02:2021-Cryptographic Failures",
    "a04:2021": "A04:2021-Insecure Design",
    "a06:2021": "A06:2021-Vulnerable and Outdated Components",
    "a07:2021": "A07:2021-Identification and Authentication Failures",
    "a08:2021": "A08:2021-Software and Data Integrity Failures",
    "a09:2021": "A09:2021-Security Logging and Monitoring Failures",
    "a10:2021": "A10:2021-Server-Side Request Forgery",
    "a10:2021-server-side request forgery (ssrf)": "A10:2021-Server-Side Request Forgery",
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
    "CWE-209",  # Error Message Containing Sensitive Information
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


def _to_2025_full(full_or_id: str) -> str | None:
    if full_or_id in OWASP_2025:
        return full_or_id
    if full_or_id in FULL_BY_ID_2025:
        return FULL_BY_ID_2025[full_or_id]
    if full_or_id in OWASP_2021:
        mapped = MAP_2021_TO_2025[OWASP_2021[full_or_id]]
        return FULL_BY_ID_2025[mapped]
    if full_or_id in FULL_BY_ID_2021:
        mapped = MAP_2021_TO_2025[full_or_id]
        return FULL_BY_ID_2025[mapped]
    return None


def normalize_owasp(value: str | None) -> tuple[str | None, list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    if value is None or str(value).strip() == "":
        return None, ["missing OWASP category"], []
    raw = str(value).strip()

    # Direct 2025 / 2021 canonical
    converted = _to_2025_full(raw)
    if converted:
        if raw in OWASP_2021 or raw.startswith("A0") and ":2021" in raw:
            warnings.append(f"normalized legacy OWASP label to {converted}")
        return converted, warnings, errors

    alias = OWASP_ALIASES.get(raw.lower())
    if alias:
        converted = _to_2025_full(alias)
        if converted:
            if ":2021" in alias:
                warnings.append(f"normalized legacy OWASP label to {converted}")
            return converted, warnings, errors

    # Prefix match A0X:2025 / A0X:2021
    upper = raw.upper()
    for full, short in OWASP_2025.items():
        if upper.startswith(short) or upper.startswith(full.upper()):
            return full, warnings, errors
    for full, short in OWASP_2021.items():
        if upper.startswith(short) or upper.startswith(full.upper()):
            mapped = MAP_2021_TO_2025[short]
            converted = FULL_BY_ID_2025[mapped]
            warnings.append(f"normalized legacy OWASP label to {converted}")
            return converted, warnings, errors

    errors.append(f"unsupported OWASP Top 10 category: {raw}")
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
    if cwe_n == "CWE-79" and owasp_n and not owasp_n.startswith("A05:2025"):
        warnings.append("CWE-79 usually maps to OWASP A05:2025 Injection")
    if cwe_n == "CWE-89" and owasp_n and not owasp_n.startswith("A05:2025"):
        warnings.append("CWE-89 usually maps to OWASP A05:2025 Injection")
    # Hygiene module emits several legitimate Top 10 mappings.
    allowed_misconfig_owasp = ("A01", "A02", "A03", "A04", "A07", "A10")
    if (
        "misconfig" in vtype
        and owasp_n
        and not any(owasp_n.startswith(prefix) for prefix in allowed_misconfig_owasp)
    ):
        warnings.append(
            "Misconfiguration findings commonly map to OWASP A02:2025 "
            "(or A01/A03/A04/A07/A10 for related hygiene checks)"
        )
    return ClassificationResult(
        cwe=cwe_n, owasp=owasp_n, warnings=warnings, errors=errors
    )


def default_classification(vulnerability_type: str) -> tuple[str | None, str | None]:
    v = vulnerability_type.lower()
    if "xss" in v or ("cross-site" in v and "script" in v):
        return "CWE-79", "A05:2025-Injection"
    if "sql" in v:
        return "CWE-89", "A05:2025-Injection"
    if "command" in v:
        return "CWE-78", "A05:2025-Injection"
    if "ssrf" in v or "server-side request" in v:
        return "CWE-918", "A01:2025-Broken Access Control"
    if "csrf" in v or "request forgery" in v:
        return "CWE-352", "A01:2025-Broken Access Control"
    if "open redirect" in v:
        return "CWE-601", "A01:2025-Broken Access Control"
    if "cryptographic" in v or "cleartext" in v:
        return "CWE-319", "A04:2025-Cryptographic Failures"
    if "exception" in v or "stack" in v or "verbose error" in v:
        return "CWE-209", "A10:2025-Mishandling of Exceptional Conditions"
    if "misconfig" in v or "header" in v:
        return "CWE-693", "A02:2025-Security Misconfiguration"
    return None, None
