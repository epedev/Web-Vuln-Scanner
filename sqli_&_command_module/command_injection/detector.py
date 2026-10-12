
"""Command-injection check for the local vulnerable training application."""

from urllib.parse import urlparse

import requests

from scanner.models import (
    Confidence,
    Finding,
    ScanResult,
    Severity,
    TestOutcome,
    VerificationStatus,
)


def _validate_local_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("Testing is restricted to the local HTTP lab.")


def check_local_target(base_url: str) -> ScanResult:
    """Check for a harmless command-output marker in the local lab."""
    _validate_local_url(base_url)
    ping_url = base_url.rstrip("/") + "/ping"
    marker = "REDOPS_CMD_TEST"
    result = ScanResult(module="command_injection")

    try:
        with requests.Session() as client:
            baseline = client.post(
                ping_url,
                data={"host": "127.0.0.1"},
                timeout=5,
            )
            test = client.post(
                ping_url,
                data={"host": f"127.0.0.1; printf {marker}"},
                timeout=5,
            )
    except requests.RequestException as exc:
        result.errors.append(f"Local lab request failed: {exc}")
        return result

    result.stats["requests_sent"] = 2

    if baseline.status_code != 200 or test.status_code != 200:
        result.outcomes.append(
            TestOutcome(
                status="inconclusive",
                url=ping_url,
                method="POST",
                parameter="host",
                reason="The baseline or test request did not return HTTP 200.",
                http_status=test.status_code,
            )
        )
        return result

    if marker not in test.text:
        result.outcomes.append(
            TestOutcome(
                status="no_finding",
                url=ping_url,
                method="POST",
                parameter="host",
                reason="The unique command-output marker was not observed.",
                http_status=test.status_code,
            )
        )
        return result

    result.findings.append(
        Finding(
            vulnerability_type="OS Command Injection",
            title="Command-injection sink pattern (lab simulation)",
            url=ping_url,
            method="POST",
            parameter="host",
            input_type="form",
            context="Ping command output (simulated lab sink)",
            payload_or_probe_id="local-command-marker-probe",
            evidence={
                "marker": marker,
                "marker_observed": True,
                "baseline_status": baseline.status_code,
                "test_status": test.status_code,
                "lab_simulation": True,
                "os_shell_executed": False,
                "note": (
                    "The VulnSight lab echoes the marker without invoking an OS shell. "
                    "Treat this as evidence of an unsafe concatenation pattern, not as "
                    "proof that the host executed operating-system commands."
                ),
            },
            detection_method="output_marker",
            confidence=Confidence.HIGH.value,
            severity=Severity.HIGH.value,
            verification_status=VerificationStatus.PROBABLE.value,
            http_status=test.status_code,
            description=(
                "A unique marker injected through the host parameter appeared in the "
                "response. Against the VulnSight lab this demonstrates a simulated "
                "command-injection sink (no OS shell is executed)."
            ),
            impact=(
                "In a real application that concatenates user input into a shell "
                "command, an attacker could run arbitrary OS commands with the web "
                "server's privileges. This lab finding proves the unsafe pattern, "
                "not live OS command execution."
            ),
            remediation=(
                "Do not invoke a shell with user-controlled input. Prefer safe APIs, "
                "pass arguments as a list with shell=False, and validate hostnames "
                "or IP addresses with an allowlist."
            ),
            cwe="CWE-78",
            module="command_injection",
        )
    )
    return result