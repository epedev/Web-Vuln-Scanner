
"""SQL injection checks for authorized local targets.

Supports:
1. Legacy login authentication-bypass probe on ``/login``
2. Crawl-map-driven error-based probes across discovered forms/params
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from scanner.models import (
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
    r"mysql_num_rows",
    r"mysqli_",
    r"sqlite.*error",
    r"sqlite3\.OperationalError",
    r"postgresql.*error",
    r"pg_query\(\).*failed",
    r"unclosed quotation mark",
    r"ODBC SQL Server Driver",
    r"SQLSTATE\[",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider",
    r"syntax error.*query",
    r"you have an error in your sql",
]

AUTH_FAIL_MARKERS = (
    "invalid credentials",
    "invalid username",
    "invalid password",
    "incorrect password",
    "incorrect username",
    "login failed",
    "authentication failed",
    "bad credentials",
    "wrong password",
    "wrong username",
    "user not found",
    "unauthorized",
)

AUTH_SUCCESS_MARKERS = (
    "logout",
    "sign out",
    "log out",
    "dashboard",
    "welcome",
    "logged in",
    "my profile",
    "account settings",
)

SQLI_PAYLOADS = (
    "admin' -- ",
    "admin'--",
    "' OR '1'='1",
    "' OR 1=1-- ",
    "1' OR '1'='1",
    "'",
    "\"",
)

PREFERRED_FIELDS = {
    "username",
    "user",
    "login",
    "email",
    "password",
    "pass",
    "q",
    "query",
    "search",
    "id",
    "name",
    "comment",
    "title",
    "message",
}


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


def _looks_like_auth_failure(status: int, text: str) -> bool:
    lowered = (text or "").lower()
    if status in {401, 403}:
        return True
    return status == 200 and any(marker in lowered for marker in AUTH_FAIL_MARKERS)


def _looks_like_auth_success(status: int, headers: dict[str, str], text: str) -> bool:
    if status in {302, 303, 307}:
        location = urlparse(headers.get("Location", "")).path or "/"
        # Redirect away from login is a success signal.
        return "login" not in location.lower()
    if status != 200:
        return False
    lowered = (text or "").lower()
    return any(marker in lowered for marker in AUTH_SUCCESS_MARKERS)


def inspect_response(
    url: str,
    parameter: str,
    test_value: str,
    response_text: str,
    http_status: int | None = None,
    method: str = "POST",
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
                method=method,
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


def _login_bypass_probe(
    client: requests.Session,
    login_url: str,
    *,
    username_field: str = "username",
    password_field: str = "password",
    timeout: float = 5.0,
) -> tuple[Finding | None, TestOutcome | None, int]:
    """Behavioral auth-bypass check; keeps legacy Invalid-credentials path."""
    baseline = client.post(
        login_url,
        data={
            username_field: "redops_invalid_user",
            password_field: "redops_invalid_password",
        },
        timeout=timeout,
        allow_redirects=False,
    )
    test = client.post(
        login_url,
        data={
            username_field: "admin' -- ",
            password_field: "redops_invalid_password",
        },
        timeout=timeout,
        allow_redirects=False,
    )
    requests_sent = 2

    legacy_ok = (
        baseline.status_code == 200
        and "Invalid credentials" in baseline.text
        and test.status_code in (302, 303)
        and urlparse(test.headers.get("Location", "")).path == "/"
    )
    flexible_ok = _looks_like_auth_failure(
        baseline.status_code, baseline.text
    ) and _looks_like_auth_success(test.status_code, dict(test.headers), test.text)

    if legacy_ok or flexible_ok:
        finding = Finding(
            vulnerability_type="SQL Injection",
            title="Possible SQL injection authentication bypass",
            url=login_url,
            method="POST",
            parameter=username_field,
            input_type="form",
            context="Login authentication",
            payload_or_probe_id="local-login-comment-probe",
            evidence={
                "baseline_status": baseline.status_code,
                "baseline_rejected_invalid_credentials": True,
                "test_status": test.status_code,
                "test_redirect": test.headers.get("Location", ""),
                "detection_mode": "legacy" if legacy_ok else "flexible",
            },
            detection_method="behavior_comparison",
            confidence=Confidence.HIGH.value,
            severity=Severity.HIGH.value,
            verification_status=VerificationStatus.PROBABLE.value,
            http_status=test.status_code,
            description=(
                "The invalid baseline login failed, but the controlled "
                "SQLi test produced an authenticated-looking response."
            ),
            impact="An authentication bypass may expose protected accounts.",
            remediation=(
                "Use parameterized SQL queries and securely hashed "
                "passwords. Verify authentication server-side."
            ),
            cwe="CWE-89",
            module="sqli",
        )
        return finding, None, requests_sent

    outcome = TestOutcome(
        status="no_finding",
        url=login_url,
        method="POST",
        parameter=username_field,
        reason="Expected authentication-bypass behavior was not observed.",
        http_status=test.status_code,
    )
    return None, outcome, requests_sent


def _iter_crawl_points(crawl_map: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Normalize crawl_map forms/pages into probeable points."""
    if not crawl_map:
        return []
    points: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for form in crawl_map.get("forms") or []:
        action = form.get("action") or form.get("url") or ""
        method = (form.get("method") or "POST").upper()
        fields = form.get("inputs") or form.get("fields") or []
        names = [
            (f.get("name") or "").strip()
            for f in fields
            if isinstance(f, dict) and f.get("name")
        ]
        if not action or not names:
            continue
        for name in names:
            key = (method, action, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                {
                    "url": action,
                    "method": method,
                    "parameter": name,
                    "field_names": names,
                    "source": "form",
                }
            )

    for page in crawl_map.get("pages") or []:
        url = page.get("url") or ""
        params = page.get("params") or []
        for param in params:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").strip()
            if not name or not url:
                continue
            key = ("GET", url, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                {
                    "url": url,
                    "method": "GET",
                    "parameter": name,
                    "field_names": [name],
                    "source": "page",
                }
            )

    for endpoint in crawl_map.get("endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        url = endpoint.get("url") or ""
        method = (endpoint.get("method") or "GET").upper()
        for param in endpoint.get("params") or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").strip()
            if not name or not url:
                continue
            key = (method, url, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(
                {
                    "url": url,
                    "method": method,
                    "parameter": name,
                    "field_names": [name],
                    "source": "endpoint",
                }
            )

    # Prefer likely injectable field names first.
    points.sort(key=lambda p: (0 if p["parameter"].lower() in PREFERRED_FIELDS else 1))
    return points


def _with_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _probe_error_based(
    client: requests.Session,
    point: dict[str, Any],
    *,
    timeout: float,
    budget: list[int],
) -> list[Finding]:
    findings: list[Finding] = []
    if budget[0] <= 0:
        return findings

    method = point["method"]
    url = point["url"]
    parameter = point["parameter"]
    field_names = point.get("field_names") or [parameter]

    for payload in SQLI_PAYLOADS:
        if budget[0] <= 0:
            break
        try:
            if method == "GET":
                target = _with_query_param(url, parameter, payload)
                resp = client.get(target, timeout=timeout, allow_redirects=False)
                observed_url = target
            else:
                data = {name: "test" for name in field_names}
                data[parameter] = payload
                resp = client.request(
                    method, url, data=data, timeout=timeout, allow_redirects=False
                )
                observed_url = url
        except requests.RequestException:
            budget[0] -= 1
            continue

        budget[0] -= 1
        inspected = inspect_response(
            url=observed_url,
            parameter=parameter,
            test_value=payload,
            response_text=resp.text or "",
            http_status=resp.status_code,
            method=method,
        )
        if inspected.findings:
            findings.extend(inspected.findings)
            break
    return findings


def check_local_target(
    base_url: str,
    crawl_map: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
    max_requests: int = 40,
) -> ScanResult:
    """Check local target for SQLi using login probe + crawl-map points."""
    _validate_local_url(base_url)
    result = ScanResult(module="sqli")
    base = base_url.rstrip("/")
    login_url = base + "/login"
    budget = [max(4, max_requests)]
    requests_sent = 0

    try:
        with requests.Session() as client:
            # 1) Legacy + flexible login bypass on /login
            try:
                finding, outcome, sent = _login_bypass_probe(
                    client, login_url, timeout=timeout
                )
                requests_sent += sent
                budget[0] -= sent
                if finding:
                    result.findings.append(finding)
                elif outcome:
                    result.outcomes.append(outcome)
            except requests.RequestException as exc:
                result.errors.append(f"Login SQLi probe failed: {exc}")

            # 2) Also probe login-like forms discovered in the crawl map
            for point in _iter_crawl_points(crawl_map):
                names = {n.lower() for n in point.get("field_names") or []}
                is_loginish = (
                    point["method"] == "POST"
                    and ("password" in names or "pass" in names)
                    and ({"username", "user", "login", "email"} & names)
                )
                if not is_loginish:
                    continue
                user_field = next(
                    (
                        n
                        for n in point["field_names"]
                        if n.lower() in {"username", "user", "login", "email"}
                    ),
                    "username",
                )
                pass_field = next(
                    (
                        n
                        for n in point["field_names"]
                        if n.lower() in {"password", "pass"}
                    ),
                    "password",
                )
                if point["url"].rstrip("/") == login_url:
                    continue  # already probed
                try:
                    finding, outcome, sent = _login_bypass_probe(
                        client,
                        point["url"],
                        username_field=user_field,
                        password_field=pass_field,
                        timeout=timeout,
                    )
                    requests_sent += sent
                    budget[0] -= sent
                    if finding:
                        result.findings.append(finding)
                    elif outcome:
                        result.outcomes.append(outcome)
                except requests.RequestException as exc:
                    result.errors.append(f"Login form probe failed: {exc}")

            # 3) Error-based probes across crawl points
            for point in _iter_crawl_points(crawl_map):
                if budget[0] <= 0:
                    break
                before = budget[0]
                new_findings = _probe_error_based(
                    client, point, timeout=timeout, budget=budget
                )
                requests_sent += before - budget[0]
                result.findings.extend(new_findings)

    except requests.RequestException as exc:
        result.errors.append(f"Local lab request failed: {exc}")
        result.stats["requests_sent"] = requests_sent
        return result

    # Deduplicate by url+parameter+title
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in result.findings:
        key = (finding.url, finding.parameter, finding.title)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    result.findings = deduped
    result.stats["requests_sent"] = requests_sent
    if crawl_map is None:
        result.limitations.append(
            "No crawl map supplied; only the /login authentication-bypass probe ran."
        )
    return result
