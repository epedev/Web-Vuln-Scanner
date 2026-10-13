
"""Security misconfiguration and hygiene checks for authorized local targets."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from scanner.models import (
    Confidence,
    Finding,
    ScanResult,
    Severity,
    TestOutcome,
    VerificationStatus,
)

SECURITY_HEADERS = (
    ("Content-Security-Policy", "CWE-693", Severity.MEDIUM.value),
    ("X-Content-Type-Options", "CWE-693", Severity.LOW.value),
    ("X-Frame-Options", "CWE-1021", Severity.MEDIUM.value),
    ("Referrer-Policy", "CWE-200", Severity.LOW.value),
    ("Strict-Transport-Security", "CWE-319", Severity.LOW.value),
)

CSRF_FIELD_HINTS = (
    "csrf",
    "csrfmiddlewaretoken",
    "_csrf",
    "authenticity_token",
    "__requestverificationtoken",
    "xsrf",
    "_token",
)

REDIRECT_PARAMS = ("next", "url", "redirect", "return", "return_url", "continue", "dest", "destination")


def _validate_local_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme not in {"http", "https"}
        or host not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Testing is restricted to the local HTTP lab.")


def _finding(**kwargs: Any) -> Finding:
    defaults = dict(
        input_type="header",
        context="HTTP response hygiene",
        payload_or_probe_id="misconfig-probe",
        detection_method="passive_inspection",
        confidence=Confidence.HIGH.value,
        verification_status=VerificationStatus.CONFIRMED.value,
        http_status=200,
        owasp="A05:2021-Security Misconfiguration",
        module="misconfig",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _check_headers(url: str, headers: dict[str, str], scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    # Case-insensitive header lookup
    lower = {k.lower(): v for k, v in headers.items()}
    for name, cwe, severity in SECURITY_HEADERS:
        if name.lower() == "strict-transport-security" and scheme != "https":
            # HSTS is not expected on plain HTTP lab targets.
            continue
        if name.lower() not in lower or not str(lower.get(name.lower(), "")).strip():
            findings.append(
                _finding(
                    vulnerability_type="Security Misconfiguration",
                    title=f"Missing {name} header",
                    url=url,
                    method="GET",
                    parameter="",
                    evidence={"missing_header": name},
                    severity=severity,
                    cwe=cwe,
                    description=(
                        f"The response from {url} does not include a {name} header. "
                        "Missing browser security controls increase impact of other flaws."
                    ),
                    impact=(
                        "Without this control, browsers may not enforce an important "
                        "defense-in-depth protection for the application."
                    ),
                    remediation=f"Configure the application/server to emit a suitable {name} header.",
                )
            )
    return findings


def _check_cookies(url: str, set_cookie_values: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_values:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.lower() for p in parts[1:]}
        attr_names = {p.split("=", 1)[0].lower() for p in parts[1:]}
        missing = []
        if "httponly" not in attr_names:
            missing.append("HttpOnly")
        if "samesite" not in attr_names:
            missing.append("SameSite")
        # Secure is recommended; on HTTP labs note as info/low
        if "secure" not in attr_names:
            missing.append("Secure")
        if not missing:
            continue
        findings.append(
            _finding(
                vulnerability_type="Security Misconfiguration",
                title=f"Cookie '{name}' missing recommended attributes",
                url=url,
                method="GET",
                parameter=name,
                input_type="cookie",
                context="Set-Cookie attributes",
                evidence={"cookie": name, "missing_attributes": missing, "raw": raw[:200]},
                severity=Severity.MEDIUM.value if "HttpOnly" in missing else Severity.LOW.value,
                cwe="CWE-614",
                description=(
                    f"Cookie '{name}' was issued without recommended attributes: "
                    + ", ".join(missing)
                    + "."
                ),
                impact=(
                    "Session cookies without HttpOnly/SameSite/Secure are easier to steal "
                    "or misuse via XSS and cross-site requests."
                ),
                remediation=(
                    "Set HttpOnly, SameSite (Lax or Strict as appropriate), and Secure "
                    "(for HTTPS) on authentication and session cookies."
                ),
                verification_status=VerificationStatus.PROBABLE.value,
            )
        )
    return findings


def _form_has_csrf(fields: list[dict[str, Any]]) -> bool:
    for field in fields:
        name = str(field.get("name") or "").lower()
        if any(hint in name for hint in CSRF_FIELD_HINTS):
            return True
    return False


def _check_csrf_forms(crawl_map: dict[str, Any] | None) -> list[Finding]:
    findings: list[Finding] = []
    if not crawl_map:
        return findings
    for form in crawl_map.get("forms") or []:
        method = (form.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        action = form.get("action") or form.get("url") or ""
        fields = form.get("fields") or form.get("inputs") or []
        if not action:
            continue
        if _form_has_csrf(fields if isinstance(fields, list) else []):
            continue
        findings.append(
            _finding(
                vulnerability_type="Cross-Site Request Forgery",
                title="State-changing form without visible CSRF token",
                url=action,
                method=method,
                parameter="",
                input_type="form",
                context="CSRF token presence in crawl-discovered form",
                payload_or_probe_id="csrf-form-inspect",
                evidence={
                    "form_action": action,
                    "method": method,
                    "field_names": [
                        f.get("name")
                        for f in fields
                        if isinstance(f, dict) and f.get("name")
                    ],
                },
                detection_method="crawl_form_inspection",
                confidence=Confidence.MEDIUM.value,
                severity=Severity.MEDIUM.value,
                verification_status=VerificationStatus.CANDIDATE.value,
                cwe="CWE-352",
                owasp="A01:2021-Broken Access Control",
                description=(
                    "A state-changing form was discovered without a recognizable CSRF "
                    "token field. This is a candidate finding and may be a false positive "
                    "if the app uses header-based or cookie-to-header CSRF defenses."
                ),
                impact=(
                    "An attacker may be able to trick a logged-in victim browser into "
                    "submitting unintended state-changing requests."
                ),
                remediation=(
                    "Use anti-CSRF tokens synchronized with the session, SameSite cookies, "
                    "and avoid relying only on secrecy of cookies for state changes."
                ),
            )
        )
    return findings


def _check_open_redirect(
    client: requests.Session,
    base_url: str,
    crawl_map: dict[str, Any] | None,
    *,
    timeout: float,
    budget: list[int],
) -> list[Finding]:
    findings: list[Finding] = []
    if not crawl_map or budget[0] <= 0:
        return findings
    external = "https://example.invalid/vulnsight-redirect-probe"
    seen: set[tuple[str, str]] = set()

    candidates: list[tuple[str, str]] = []
    for page in crawl_map.get("pages") or []:
        url = page.get("url") or ""
        for param in page.get("params") or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").lower()
            if name in REDIRECT_PARAMS and url:
                candidates.append((url, param.get("name") or name))
    for endpoint in crawl_map.get("endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        url = endpoint.get("url") or ""
        for param in endpoint.get("params") or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").lower()
            if name in REDIRECT_PARAMS and url:
                candidates.append((url, param.get("name") or name))

    for url, param in candidates:
        key = (url, param)
        if key in seen or budget[0] <= 0:
            continue
        seen.add(key)
        parsed = urlparse(url)
        pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != param]
        pairs.append((param, external))
        probe = urlunparse(parsed._replace(query=urlencode(pairs)))
        try:
            resp = client.get(probe, timeout=timeout, allow_redirects=False)
            budget[0] -= 1
        except requests.RequestException:
            budget[0] -= 1
            continue
        location = resp.headers.get("Location", "")
        if resp.status_code in {301, 302, 303, 307, 308} and external.rstrip("/") in location:
            findings.append(
                _finding(
                    vulnerability_type="Open Redirect",
                    title=f"Open redirect candidate via '{param}'",
                    url=url,
                    method="GET",
                    parameter=param,
                    input_type="query",
                    context="Redirect parameter handling",
                    payload_or_probe_id="open-redirect-probe",
                    evidence={
                        "probe_url": probe,
                        "status": resp.status_code,
                        "location": location,
                    },
                    detection_method="redirect_location_compare",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.MEDIUM.value,
                    verification_status=VerificationStatus.PROBABLE.value,
                    http_status=resp.status_code,
                    cwe="CWE-601",
                    owasp="A01:2021-Broken Access Control",
                    description=(
                        "A redirect parameter accepted an external URL and the response "
                        "Location header pointed outside the application origin."
                    ),
                    impact=(
                        "Attackers can craft links that send users to malicious sites while "
                        "appearing to start from a trusted host."
                    ),
                    remediation=(
                        "Allowlist internal redirect targets; reject absolute external URLs "
                        "in redirect parameters."
                    ),
                )
            )
    return findings


def check_local_target(
    base_url: str,
    crawl_map: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
    max_requests: int = 20,
) -> ScanResult:
    """Run security-hygiene checks against an authorized local target."""
    _validate_local_url(base_url)
    result = ScanResult(module="misconfig")
    base = base_url.rstrip("/") + "/"
    budget = [max(1, max_requests)]
    requests_sent = 0

    try:
        with requests.Session() as client:
            resp = client.get(base, timeout=timeout, allow_redirects=True)
            requests_sent += 1
            budget[0] -= 1
            final_url = str(resp.url)
            headers = {k: v for k, v in resp.headers.items()}
            # Collect all Set-Cookie headers if available
            set_cookies: list[str] = []
            if hasattr(resp.raw, "headers"):
                getlist = getattr(resp.raw.headers, "getlist", None)
                if callable(getlist):
                    set_cookies = list(getlist("Set-Cookie") or [])
            if not set_cookies and resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie", "")]

            result.findings.extend(_check_headers(final_url, headers, urlparse(final_url).scheme))
            result.findings.extend(_check_cookies(final_url, set_cookies))
            result.findings.extend(_check_csrf_forms(crawl_map))
            result.findings.extend(
                _check_open_redirect(
                    client, base_url, crawl_map, timeout=timeout, budget=budget
                )
            )
            requests_sent += max(0, max_requests - 1 - budget[0])
    except requests.RequestException as exc:
        result.errors.append(f"Misconfig probe failed: {exc}")
        result.stats["requests_sent"] = requests_sent
        return result

    # Dedup
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for f in result.findings:
        key = (f.title, f.url, f.parameter or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    result.findings = deduped
    result.stats["requests_sent"] = requests_sent
    result.limitations.append(
        "CSRF checks are crawl-form inspections and may false-positive when "
        "token-less double-submit or custom header CSRF defenses are used."
    )
    result.limitations.append(
        "HSTS is only evaluated for HTTPS responses; plain HTTP labs skip HSTS."
    )
    return result
