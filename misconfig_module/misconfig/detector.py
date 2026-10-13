
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
SSRF_PARAMS = ("url", "uri", "fetch", "feed", "proxy", "target_url", "page_url", "webhook", "callback")
DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")


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
        owasp="A02:2025-Security Misconfiguration",
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
            owasp = (
                "A04:2025-Cryptographic Failures"
                if name.lower() == "strict-transport-security"
                else "A02:2025-Security Misconfiguration"
            )
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
                    owasp=owasp,
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
                owasp="A07:2025-Authentication Failures",
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
                owasp="A01:2025-Broken Access Control",
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

    def _add_url(url: str) -> None:
        if not url:
            return
        parsed = urlparse(url)
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if name.lower() in REDIRECT_PARAMS:
                # Probe using the URL without forcing a prior crawl visit.
                candidates.append((url, name))

    for page in crawl_map.get("pages") or []:
        url = page.get("url") or ""
        for param in page.get("params") or []:
            if not isinstance(param, dict):
                continue
            name = (param.get("name") or "").lower()
            if name in REDIRECT_PARAMS and url:
                candidates.append((url, param.get("name") or name))
        for link in page.get("links") or []:
            _add_url(link)
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
            _add_url(url)

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
        loc = location.strip()
        external_hit = (
            external.rstrip("/") in loc
            or loc.rstrip("/") == external.rstrip("/")
            or loc.startswith(external)
        )
        if resp.status_code in {301, 302, 303, 307, 308} and external_hit:
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
                    owasp="A01:2025-Broken Access Control",
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



def _check_tech_disclosure(url: str, headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    lower = {k.lower(): (k, v) for k, v in headers.items()}
    for name in DISCLOSURE_HEADERS:
        hit = lower.get(name.lower())
        if not hit:
            continue
        original, value = hit
        if not str(value).strip():
            continue
        findings.append(
            _finding(
                vulnerability_type="Security Misconfiguration",
                title=f"Technology disclosure via {original} header",
                url=url,
                method="GET",
                parameter="",
                evidence={"header": original, "value": str(value)[:160]},
                severity=Severity.INFO.value,
                confidence=Confidence.HIGH.value,
                verification_status=VerificationStatus.CONFIRMED.value,
                cwe="CWE-200",
                owasp="A03:2025-Software Supply Chain Failures",
                description=(
                    f"The response discloses component information through the "
                    f"{original} header ({value!s})."
                ),
                impact=(
                    "Attackers can fingerprint the stack and prioritize known component "
                    "weaknesses more quickly."
                ),
                remediation=(
                    "Remove or generalize verbose server/framework headers in production."
                ),
            )
        )
    return findings


def _check_cleartext_transport(base_url: str, crawl_map: dict[str, Any] | None) -> list[Finding]:
    findings: list[Finding] = []
    if urlparse(base_url).scheme != "http":
        return findings
    loginish = False
    for form in (crawl_map or {}).get("forms") or []:
        names = {
            str(f.get("name") or "").lower()
            for f in (form.get("fields") or form.get("inputs") or [])
            if isinstance(f, dict)
        }
        if {"password", "pass"} & names:
            loginish = True
            break
    if not loginish and "/login" in (base_url.lower() + str(crawl_map)):
        loginish = True
    if not loginish:
        return findings
    findings.append(
        _finding(
            vulnerability_type="Cryptographic Failure",
            title="Login/password form served over cleartext HTTP",
            url=base_url.rstrip("/") + "/login",
            method="GET",
            parameter="password",
            input_type="form",
            context="Transport security for authentication",
            evidence={"scheme": "http", "note": "Lab/HTTP target exposes password form without TLS"},
            severity=Severity.HIGH.value,
            confidence=Confidence.HIGH.value,
            verification_status=VerificationStatus.PROBABLE.value,
            cwe="CWE-319",
            owasp="A04:2025-Cryptographic Failures",
            description=(
                "A password-bearing login form is reachable over unencrypted HTTP, "
                "so credentials may be intercepted on the network path."
            ),
            impact=(
                "Credentials and session tokens can be captured by on-path attackers "
                "when TLS is not used."
            ),
            remediation=(
                "Serve authentication only over HTTPS and set Secure on session cookies."
            ),
        )
    )
    return findings


def _iter_ssrf_candidates(crawl_map: dict[str, Any] | None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    if not crawl_map:
        return out

    def add(url: str, method: str, param: str) -> None:
        key = (method.upper(), url, param)
        if not url or not param or key in seen:
            return
        if param.lower() not in SSRF_PARAMS:
            return
        # Avoid double-counting pure open-redirect params already handled separately
        # unless name is strongly SSRF-like.
        seen.add(key)
        out.append({"url": url, "method": method.upper(), "parameter": param})

    for page in crawl_map.get("pages") or []:
        url = page.get("url") or ""
        for param in page.get("params") or []:
            if isinstance(param, dict):
                add(url, "GET", param.get("name") or "")
        for link in page.get("links") or []:
            parsed = urlparse(link)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                add(link, "GET", name)
    for form in crawl_map.get("forms") or []:
        action = form.get("action") or form.get("url") or ""
        method = (form.get("method") or "POST").upper()
        for field in form.get("fields") or form.get("inputs") or []:
            if isinstance(field, dict):
                add(action, method, field.get("name") or "")
    return out


def _check_ssrf(
    client: requests.Session,
    crawl_map: dict[str, Any] | None,
    *,
    timeout: float,
    budget: list[int],
) -> list[Finding]:
    findings: list[Finding] = []
    marker_host = "127.0.0.1:9"
    probe_target = f"http://{marker_host}/vulnsight-ssrf-probe"
    for point in _iter_ssrf_candidates(crawl_map):
        if budget[0] <= 0:
            break
        url, method, param = point["url"], point["method"], point["parameter"]
        # Skip classic redirect-only param names unless strongly SSRF-named
        if param.lower() in REDIRECT_PARAMS and param.lower() not in {"url", "uri"}:
            continue
        try:
            if method == "GET":
                parsed = urlparse(url)
                pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != param]
                pairs.append((param, probe_target))
                probe_url = urlunparse(parsed._replace(query=urlencode(pairs)))
                baseline = client.get(url, timeout=timeout, allow_redirects=False)
                test = client.get(probe_url, timeout=timeout, allow_redirects=False)
            else:
                baseline = client.request(method, url, data={param: "http://127.0.0.1/"}, timeout=timeout, allow_redirects=False)
                test = client.request(method, url, data={param: probe_target}, timeout=timeout, allow_redirects=False)
            budget[0] -= 2
        except requests.RequestException:
            budget[0] -= 1
            continue

        body = (test.text or "")
        signal = (
            "vulnsight-ssrf-probe" in body
            or "Connection refused" in body
            or "Failed to connect" in body
            or "Errno 111" in body
            or marker_host in body
            or (test.status_code >= 500 and baseline.status_code < 500)
        )
        if not signal:
            # Still raise a low-confidence candidate when SSRF-like param accepts absolute URL without erroring immediately as validation failure
            if test.status_code == 200 and len(body) != len(baseline.text or ""):
                signal = True
        if not signal:
            continue
        findings.append(
            _finding(
                vulnerability_type="Server-Side Request Forgery",
                title=f"SSRF candidate via '{param}'",
                url=url,
                method=method,
                parameter=param,
                input_type="query" if method == "GET" else "form",
                context="Server-side URL fetch parameter",
                payload_or_probe_id="ssrf-closed-port-probe",
                evidence={
                    "probe_target": probe_target,
                    "baseline_status": baseline.status_code,
                    "test_status": test.status_code,
                    "signal": True,
                },
                detection_method="ssrf_param_probe",
                confidence=Confidence.MEDIUM.value,
                severity=Severity.HIGH.value,
                verification_status=VerificationStatus.CANDIDATE.value,
                http_status=test.status_code,
                cwe="CWE-918",
                owasp="A01:2025-Broken Access Control",
                description=(
                    f"Parameter '{param}' accepted an attacker-controlled absolute URL and "
                    "the response showed signs of server-side fetch/error handling for that host."
                ),
                impact=(
                    "SSRF can expose internal services, cloud metadata endpoints, or port scan "
                    "the internal network via the application server."
                ),
                remediation=(
                    "Avoid passing user input into server-side HTTP clients; allowlist schemes "
                    "and destinations; block link-local and loopback ranges."
                ),
            )
        )
    return findings




def _check_verbose_errors(
    client: requests.Session,
    base_url: str,
    *,
    timeout: float,
    budget: list[int],
) -> list[Finding]:
    """Probe for sensitive error/stack disclosure (OWASP A10:2025)."""
    findings: list[Finding] = []
    if budget[0] <= 0:
        return findings
    probe = base_url.rstrip("/") + "/vulnsight-exception-probe-%s" % "zz9"
    try:
        resp = client.get(probe, timeout=timeout, allow_redirects=True)
        budget[0] -= 1
    except requests.RequestException:
        budget[0] -= 1
        return findings
    raw_text = getattr(resp, "text", "")
    body = raw_text if isinstance(raw_text, str) else ""
    status = getattr(resp, "status_code", 0)
    try:
        status_i = int(status)
    except (TypeError, ValueError):
        status_i = 0
    signals = []
    for marker in (
        "Traceback (most recent call last)",
        "Werkzeug Debugger",
        "jinja2.exceptions",
        "sqlalchemy.exc",
        "NullPointerException",
        "Stacktrace:",
        "at java.",
        "PHP Fatal error",
        "Warning: include(",
        "Django Version:",
    ):
        if marker in body:
            signals.append(marker)
    # Generic verbose 500 with long diagnostic body
    if status_i >= 500 and len(body) > 800 and ("exception" in body.lower() or "error" in body.lower()):
        signals.append("verbose_5xx_body")
    if not signals:
        return findings
    findings.append(
        _finding(
            vulnerability_type="Exception Handling Failure",
            title="Verbose error / stack information disclosure",
            url=probe,
            method="GET",
            parameter="",
            input_type="path",
            context="Error handling / exceptional conditions",
            payload_or_probe_id="exception-probe",
            evidence={"status": status_i, "signals": signals, "body_excerpt": body[:240]},
            detection_method="verbose_error_probe",
            confidence=Confidence.MEDIUM.value,
            severity=Severity.MEDIUM.value,
            verification_status=VerificationStatus.PROBABLE.value,
            http_status=status_i,
            cwe="CWE-209",
            owasp="A10:2025-Mishandling of Exceptional Conditions",
            description=(
                "A crafted request produced a response that appears to disclose "
                "stack traces or detailed diagnostic error information."
            ),
            impact=(
                "Sensitive error details help attackers map frameworks, paths, and "
                "internal failures useful for further exploitation."
            ),
            remediation=(
                "Return generic client errors; log details server-side only; disable "
                "framework debug/diagnostic pages in production."
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
            result.findings.extend(_check_tech_disclosure(final_url, headers))
            result.findings.extend(_check_cookies(final_url, set_cookies))
            result.findings.extend(_check_cleartext_transport(base_url, crawl_map))
            result.findings.extend(_check_csrf_forms(crawl_map))
            result.findings.extend(
                _check_open_redirect(
                    client, base_url, crawl_map, timeout=timeout, budget=budget
                )
            )
            result.findings.extend(
                _check_ssrf(client, crawl_map, timeout=timeout, budget=budget)
            )
            result.findings.extend(
                _check_verbose_errors(client, base_url, timeout=timeout, budget=budget)
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
    result.limitations.append(
        "SSRF probes are candidate-level and use closed-port/error signals; validate manually."
    )
    result.limitations.append(
        "OWASP A06/A08/A09 (2025) have limited or no dynamic coverage in VulnSight."
    )
    return result
