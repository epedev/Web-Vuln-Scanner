
"""SQL injection checks for the local vulnerable training application."""

import re
from urllib.parse import urlparse

import requests

from xss_module.scanner.models import (
    Confidence,
    Finding,
    ScanResult,
    Severity,
    TestOutcome,
    VerificationStatus,
)

SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"mysql_fetch",
    r"sqlite.*error",
    r"sqlite3\.OperationalError",
    r"postgresql.*error",
    r"pg_query\(\).*failed",
    r"unclosed quotation mark",
    r"ODBC SQL Server Driver",
]


def _validate_local_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Testing is restricted to the local HTTP lab.")


def inspect_response(
    url: str,
    parameter: str,
    test_value: str,
    response_text: str,
    http_status: int | None = None,
) -> ScanResult:
    """Identify database error signatures in an already-observed response."""
    matches = [
        pattern
        for pattern in SQL_ERROR_PATTERNS
        if re.search(pattern, response_text, re.IGNORECASE)
    ]

    result = ScanResult(module="sqli")
    if matches:
        result.findings.append(
            Finding(
                vulnerability_type="SQL Injection",
                title="Possible error-based SQL injection",
                url=url,
                method="POST",
                parameter=parameter,
                input_type="form",
                context="Database error in HTTP response",
                payload_or_probe_id=test_value,
                evidence={"matched_signatures": matches},
                detection_method="error_signature",
                confidence=Confidence.MEDIUM.value,
                severity=Severity.HIGH.value,
                verification_status=VerificationStatus.CANDIDATE.value,
                http_status=http_status,
                description="The response contains a database error signature.",
                impact="Database details may be exposed; injection may be possible.",
                remediation=(
                    "Use parameterized queries and avoid returning database "
                    "errors to clients."
                ),
                cwe="CWE-89",
                module="sqli",
            )
        )
    return result


def check_local_target(base_url: str) -> ScanResult:
    """Check the documented login behavior in the local training app."""
    _validate_local_url(base_url)
    login_url = base_url.rstrip("/") + "/login"
    result = ScanResult(module="sqli")

    try:
        with requests.Session() as client:
            baseline = client.post(
                login_url,
                data={
                    "username": "redops_invalid_user",
                    "password": "redops_invalid_password",
                },
                timeout=5,
                allow_redirects=False,
            )
            test = client.post(
                login_url,
                data={
                    "username": "admin' -- ",
                    "password": "redops_invalid_password",
                },
                timeout=5,
                allow_redirects=False,
            )
    except requests.RequestException as exc:
        result.errors.append(f"Local lab request failed: {exc}")
        return result

    baseline_failed = (
        baseline.status_code == 200
        and "Invalid credentials" in baseline.text
    )
    redirected_home = (
        test.status_code in (302, 303)
        and urlparse(test.headers.get("Location", "")).path == "/"
    )

    if baseline_failed and redirected_home:
        result.findings.append(
            Finding(
                vulnerability_type="SQL Injection",
                title="Possible SQL injection authentication bypass",
                url=login_url,
                method="POST",
                parameter="username",
                input_type="form",
                context="Login authentication",
                payload_or_probe_id="local-login-comment-probe",
                evidence={
                    "baseline_status": baseline.status_code,
                    "baseline_rejected_invalid_credentials": True,
                    "test_status": test.status_code,
                    "test_redirect": test.headers.get("Location", ""),
                },
                detection_method="behavior_comparison",
                confidence=Confidence.HIGH.value,
                severity=Severity.HIGH.value,
                verification_status=VerificationStatus.PROBABLE.value,
                http_status=test.status_code,
                description=(
                    "The invalid baseline login failed, but the controlled "
                    "SQLi test redirected to the homepage."
                ),
                impact="An authentication bypass may expose protected accounts.",
                remediation=(
                    "Use parameterized SQL queries and securely hashed "
                    "passwords. Verify authentication server-side."
                ),
                cwe="CWE-89",
                module="sqli",
            )
        )
    else:
        result.outcomes.append(
            __import__(
                "xss_module.scanner.models", fromlist=["TestOutcome"]
            ).TestOutcome(
                status="no_finding",
                url=login_url,
                method="POST",
                parameter="username",
                reason="Expected authentication-bypass behavior was not observed.",
                http_status=test.status_code,
            )
        )

    result.stats["requests_sent"] = 2
    return result