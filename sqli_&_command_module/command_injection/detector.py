
"""Command-injection checks for authorized local targets.

Supports:
1. Legacy ``/ping`` marker probe used by the original training lab
2. Crawl-map-driven probes on host/cmd-like parameters
"""

from __future__ import annotations

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

MARKER = "REDOPS_CMD_TEST"
PREFERRED_PARAMS = {
    "host",
    "ip",
    "hostname",
    "cmd",
    "command",
    "ping",
    "exec",
    "execute",
    "query",
    "target",
    "address",
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


def _with_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _build_finding(
    *,
    url: str,
    method: str,
    parameter: str,
    baseline_status: int,
    test_status: int,
) -> Finding:
    return Finding(
        vulnerability_type="OS Command Injection",
        title="Command-injection sink pattern detected",
        url=url,
        method=method,
        parameter=parameter,
        input_type="form",
        context="Command output / unsafe concatenation sink",
        payload_or_probe_id="local-command-marker-probe",
        evidence={
            "marker": MARKER,
            "marker_observed": True,
            "baseline_status": baseline_status,
            "test_status": test_status,
            "lab_simulation": True,
            "os_shell_executed": False,
            "note": (
                "A unique marker injected through a command-like parameter appeared "
                "in the response. Treat this as evidence of an unsafe concatenation "
                "pattern, not as proof that the host executed operating-system commands."
            ),
        },
        detection_method="output_marker",
        confidence=Confidence.HIGH.value,
        severity=Severity.HIGH.value,
        verification_status=VerificationStatus.PROBABLE.value,
        http_status=test_status,
        description=(
            "A unique marker injected through a command-like parameter appeared in "
            "the response, indicating an unsafe sink pattern."
        ),
        impact=(
            "In a real application that concatenates user input into a shell "
            "command, an attacker could run arbitrary OS commands with the web "
            "server's privileges."
        ),
        remediation=(
            "Do not invoke a shell with user-controlled input. Prefer safe APIs, "
            "pass arguments as a list with shell=False, and validate hostnames "
            "or IP addresses with an allowlist."
        ),
        cwe="CWE-78",
        module="command_injection",
    )


def _probe_endpoint(
    client: requests.Session,
    *,
    url: str,
    method: str,
    parameter: str,
    field_names: list[str] | None = None,
    timeout: float,
    payloads: tuple[tuple[str, str], ...] | None = None,
) -> tuple[Finding | None, TestOutcome | None]:
    method = method.upper()
    fields = field_names or [parameter]
    payloads = payloads or (
        ("127.0.0.1", f"127.0.0.1; printf {MARKER}"),
        ("127.0.0.1", f"127.0.0.1|echo {MARKER}"),
        ("x", f"x;printf {MARKER}"),
    )

    last_outcome: TestOutcome | None = None
    for baseline_value, test_value in payloads:
        try:
            if method == "GET":
                baseline = client.get(
                    _with_query_param(url, parameter, baseline_value),
                    timeout=timeout,
                )
                test = client.get(
                    _with_query_param(url, parameter, test_value),
                    timeout=timeout,
                )
            else:
                baseline_data = {name: "test" for name in fields}
                baseline_data[parameter] = baseline_value
                test_data = {name: "test" for name in fields}
                test_data[parameter] = test_value
                if method == "POST":
                    baseline = client.post(url, data=baseline_data, timeout=timeout)
                    test = client.post(url, data=test_data, timeout=timeout)
                else:
                    baseline = client.request(
                        method, url, data=baseline_data, timeout=timeout
                    )
                    test = client.request(method, url, data=test_data, timeout=timeout)
        except requests.RequestException as exc:
            return None, TestOutcome(
                status="failed",
                url=url,
                method=method,
                parameter=parameter,
                reason=f"Request failed: {exc}",
            )

        if baseline.status_code != 200 or test.status_code != 200:
            last_outcome = TestOutcome(
                status="inconclusive",
                url=url,
                method=method,
                parameter=parameter,
                reason="The baseline or test request did not return HTTP 200.",
                http_status=test.status_code,
            )
            continue

        if MARKER in (baseline.text or ""):
            continue
        if MARKER not in (test.text or ""):
            last_outcome = TestOutcome(
                status="no_finding",
                url=url,
                method=method,
                parameter=parameter,
                reason="The unique command-output marker was not observed.",
                http_status=test.status_code,
            )
            continue

        return (
            _build_finding(
                url=url,
                method=method,
                parameter=parameter,
                baseline_status=baseline.status_code,
                test_status=test.status_code,
            ),
            None,
        )

    return None, last_outcome


def _iter_crawl_points(crawl_map: dict[str, Any] | None) -> list[dict[str, Any]]:
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
                }
            )

    for page in crawl_map.get("pages") or []:
        url = page.get("url") or ""
        for param in page.get("params") or []:
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
                }
            )

    points.sort(
        key=lambda p: (0 if p["parameter"].lower() in PREFERRED_PARAMS else 1, p["url"])
    )
    return points


def check_local_target(
    base_url: str,
    crawl_map: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
    max_probes: int = 12,
) -> ScanResult:
    """Check for command-injection sink patterns on the local target."""
    _validate_local_url(base_url)
    result = ScanResult(module="command_injection")
    base = base_url.rstrip("/")
    ping_url = base + "/ping"
    requests_sent = 0

    try:
        with requests.Session() as client:
            finding, outcome = _probe_endpoint(
                client,
                url=ping_url,
                method="POST",
                parameter="host",
                field_names=["host"],
                timeout=timeout,
                payloads=(("127.0.0.1", f"127.0.0.1; printf {MARKER}"),),
            )
            requests_sent += 2
            if finding:
                # Preserve legacy wording for the training-lab /ping sink.
                finding.title = "Command-injection sink pattern (lab simulation)"
                finding.context = "Ping command output (simulated lab sink)"
                finding.description = (
                    "A unique marker injected through the host parameter appeared in the "
                    "response. Against the VulnSight lab this demonstrates a simulated "
                    "command-injection sink (no OS shell is executed)."
                )
                result.findings.append(finding)
            elif outcome:
                result.outcomes.append(outcome)

            probed = 0
            for point in _iter_crawl_points(crawl_map):
                if probed >= max_probes:
                    break
                # Prefer command-like params; still allow a few generic ones on /ping-like URLs.
                pname = point["parameter"].lower()
                url_l = point["url"].lower()
                interesting = (
                    pname in PREFERRED_PARAMS
                    or "ping" in url_l
                    or "cmd" in url_l
                    or "exec" in url_l
                )
                if not interesting:
                    continue
                if point["url"].rstrip("/") == ping_url and pname == "host":
                    continue
                finding, outcome = _probe_endpoint(
                    client,
                    url=point["url"],
                    method=point["method"],
                    parameter=point["parameter"],
                    field_names=point.get("field_names"),
                    timeout=timeout,
                )
                requests_sent += 2
                probed += 1
                if finding:
                    result.findings.append(finding)
                elif outcome:
                    result.outcomes.append(outcome)
    except requests.RequestException as exc:
        result.errors.append(f"Local lab request failed: {exc}")
        result.stats["requests_sent"] = requests_sent
        return result

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
            "No crawl map supplied; only the /ping marker probe ran."
        )
    return result
