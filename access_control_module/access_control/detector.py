"""Access control checks (IDOR + broken access control) for the local
vulnerable training application."""

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


def login(base_url: str, username: str, password: str) -> requests.Session:
    """Authenticate against the local lab app and return the resulting session."""
    _validate_local_url(base_url)
    session = requests.Session()
    session.post(
        base_url.rstrip("/") + "/login",
        data={"username": username, "password": password},
        timeout=5,
    )
    return session


def check_idor(
    base_url: str,
    authenticated_session: requests.Session,
    own_user_id: int,
    probe_ids: list[int],
) -> ScanResult:
    """IDOR check: with a session authenticated as one user, request other
    users' profile resources by substituting the ID. A properly
    access-controlled endpoint rejects IDs that aren't the authenticated
    user's own (401/403, or a redirect); this checks whether the app
    instead serves the data with a 200."""
    _validate_local_url(base_url)
    result = ScanResult(module="access_control")

    for pid in probe_ids:
        if pid == own_user_id:
            continue
        url = base_url.rstrip("/") + f"/profile/{pid}"
        try:
            resp = authenticated_session.get(url, timeout=5, allow_redirects=False)
        except requests.RequestException as exc:
            result.errors.append(f"IDOR probe failed for {url}: {exc}")
            continue

        if resp.status_code == 200:
            result.findings.append(
                Finding(
                    vulnerability_type="Insecure Direct Object Reference",
                    title=f"IDOR: profile {pid} accessible to a different authenticated user",
                    url=url,
                    method="GET",
                    parameter="user_id",
                    input_type="path",
                    context="Profile resource access control",
                    payload_or_probe_id=str(pid),
                    evidence={
                        "requested_as_own_id": own_user_id,
                        "requested_target_id": pid,
                        "response_status": resp.status_code,
                        "response_length": len(resp.text),
                    },
                    detection_method="authorization_boundary_probe",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.HIGH.value,
                    verification_status=VerificationStatus.CONFIRMED.value,
                    http_status=resp.status_code,
                    description=(
                        f"A session authenticated as user {own_user_id} retrieved user "
                        f"{pid}'s profile data via direct ID substitution, with no "
                        "ownership or role check on the server."
                    ),
                    impact=(
                        "Any authenticated user can enumerate and read every other "
                        "user's profile data (email, bio) by incrementing an integer."
                    ),
                    remediation=(
                        "Verify server-side that the requested resource belongs to the "
                        "authenticated session (or that an explicit role grants cross-"
                        "user access) before returning data — not merely that a session "
                        "exists."
                    ),
                    cwe="CWE-639",
                    owasp="A01:2021-Broken Access Control",
                    module="access_control",
                )
            )
        else:
            result.outcomes.append(
                TestOutcome(
                    status="no_finding",
                    url=url,
                    method="GET",
                    parameter="user_id",
                    reason=(
                        f"Access to a different user's profile was not granted "
                        f"(HTTP {resp.status_code})."
                    ),
                    http_status=resp.status_code,
                )
            )

    result.stats["requests_sent"] = len([p for p in probe_ids if p != own_user_id])
    return result


def check_broken_access_control(
    base_url: str,
    low_privilege_session: requests.Session,
    admin_path: str = "/admin",
) -> ScanResult:
    """Broken access control check: with a session authenticated as a
    non-privileged user, request a path conventionally reserved for
    privileged roles (e.g. /admin). Flags a 200 as the signature of a
    route that checks 'is logged in' but not 'is allowed.'"""
    _validate_local_url(base_url)
    result = ScanResult(module="access_control")
    url = base_url.rstrip("/") + admin_path

    try:
        resp = low_privilege_session.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException as exc:
        result.errors.append(f"Broken access control probe failed for {url}: {exc}")
        return result

    result.stats["requests_sent"] = 1

    if resp.status_code == 200:
        result.findings.append(
            Finding(
                vulnerability_type="Broken Access Control",
                title=(
                    f"Privileged path {admin_path} reachable by a non-privileged "
                    "authenticated session"
                ),
                url=url,
                method="GET",
                parameter="",
                input_type="session",
                context="Role-based access control on a privileged route",
                payload_or_probe_id="low_privilege_session",
                evidence={
                    "response_status": resp.status_code,
                    "response_length": len(resp.text),
                },
                detection_method="authorization_boundary_probe",
                confidence=Confidence.HIGH.value,
                severity=Severity.CRITICAL.value,
                verification_status=VerificationStatus.CONFIRMED.value,
                http_status=resp.status_code,
                description=(
                    f"A session authenticated as a non-privileged user reached "
                    f"{admin_path} successfully. The route checks only that a session "
                    "exists, not that the session holds the required privilege/role."
                ),
                impact=(
                    "Any authenticated user, not just admins, can access privileged "
                    "functionality and data (e.g. the full user table, including which "
                    "accounts are admins)."
                ),
                remediation=(
                    "Check the authenticated session's role/permission explicitly "
                    "before serving privileged routes (e.g. session['is_admin']), not "
                    "just that a session exists."
                ),
                cwe="CWE-284",
                owasp="A01:2021-Broken Access Control",
                module="access_control",
            )
        )
    else:
        result.outcomes.append(
            TestOutcome(
                status="no_finding",
                url=url,
                method="GET",
                parameter="",
                reason=(
                    f"Privileged path was not reachable by a non-privileged session "
                    f"(HTTP {resp.status_code})."
                ),
                http_status=resp.status_code,
            )
        )

    return result


def check_local_target(base_url: str) -> ScanResult:
    """Full check against the local training app: logs in as two seeded
    non-admin users, runs the IDOR probe between them, then logs in as a
    non-admin user and runs the broken-access-control probe against
    /admin. Matches the house convention of exposing one top-level
    check_local_target() entrypoint, same as the sqli and
    command_injection modules."""
    _validate_local_url(base_url)
    combined = ScanResult(module="access_control")

    try:
        alice_session = login(base_url, "alice", "alice123")
        bob_session = login(base_url, "bob", "bobpass")
    except requests.RequestException as exc:
        combined.errors.append(f"Login failed during access_control setup: {exc}")
        return combined

    idor_result = check_idor(
        base_url, alice_session, own_user_id=1, probe_ids=[1, 2, 3]
    )
    bac_result = check_broken_access_control(base_url, alice_session)

    combined.findings.extend(idor_result.findings)
    combined.findings.extend(bac_result.findings)
    combined.outcomes.extend(idor_result.outcomes)
    combined.outcomes.extend(bac_result.outcomes)
    combined.errors.extend(idor_result.errors)
    combined.errors.extend(bac_result.errors)
    combined.stats["requests_sent"] = (
        idor_result.stats.get("requests_sent", 0)
        + bac_result.stats.get("requests_sent", 0)
        + 2  # the two logins
    )

    bob_session.close()
    return combined
