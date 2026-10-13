"""Access control checks (IDOR + broken access control) for authorized local targets.

Supports:
1. Legacy seeded users (alice/bob) against ``/profile/{id}`` and ``/admin``
2. Crawl-map discovery of profile/admin paths
3. Unauthenticated IDOR/BAC probes when login credentials are unavailable
"""

from __future__ import annotations

import re
from typing import Any
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

PROFILE_RE = re.compile(r"/profile/(\d+)/?$", re.IGNORECASE)
ADMIN_HINTS = ("/admin", "/administrator", "/dashboard/admin", "/manage")


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


def login(base_url: str, username: str, password: str, login_path: str = "/login") -> requests.Session:
    """Authenticate against the local lab app and return the resulting session."""
    _validate_local_url(base_url)
    session = requests.Session()
    session.post(
        base_url.rstrip("/") + login_path,
        data={"username": username, "password": password},
        timeout=5,
    )
    return session


def check_idor(
    base_url: str,
    authenticated_session: requests.Session,
    own_user_id: int,
    probe_ids: list[int],
    *,
    profile_template: str = "/profile/{id}",
) -> ScanResult:
    """IDOR check via direct object ID substitution on profile resources."""
    _validate_local_url(base_url)
    result = ScanResult(module="access_control")

    for pid in probe_ids:
        if pid == own_user_id:
            continue
        path = profile_template.format(id=pid)
        if not path.startswith("/"):
            path = "/" + path
        url = base_url.rstrip("/") + path
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
                        "user's profile data by incrementing an integer."
                    ),
                    remediation=(
                        "Verify server-side that the requested resource belongs to the "
                        "authenticated session (or that an explicit role grants cross-"
                        "user access) before returning data — not merely that a session "
                        "exists."
                    ),
                    cwe="CWE-639",
                    owasp="A01:2025-Broken Access Control",
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
    """Broken access control check against a privileged path."""
    _validate_local_url(base_url)
    result = ScanResult(module="access_control")
    if not admin_path.startswith("/"):
        admin_path = "/" + admin_path
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
                    "functionality and data."
                ),
                remediation=(
                    "Check the authenticated session's role/permission explicitly "
                    "before serving privileged routes, not just that a session exists."
                ),
                cwe="CWE-284",
                owasp="A01:2025-Broken Access Control",
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


def _discover_from_crawl(
    base_url: str, crawl_map: dict[str, Any] | None
) -> tuple[str, list[int], list[str]]:
    """Return profile template, probe ids, and admin paths from crawl map."""
    profile_template = "/profile/{id}"
    probe_ids = [1, 2, 3]
    admin_paths = ["/admin"]
    if not crawl_map:
        return profile_template, probe_ids, admin_paths

    found_ids: list[int] = []
    found_admins: list[str] = []
    base = base_url.rstrip("/")

    urls: list[str] = []
    for page in crawl_map.get("pages") or []:
        if page.get("url"):
            urls.append(page["url"])
        for link in page.get("links") or []:
            urls.append(link)
    for endpoint in crawl_map.get("endpoints") or []:
        if isinstance(endpoint, dict) and endpoint.get("url"):
            urls.append(endpoint["url"])
        elif isinstance(endpoint, str):
            urls.append(endpoint)

    for url in urls:
        path = urlparse(url).path or ""
        m = PROFILE_RE.search(path)
        if m:
            found_ids.append(int(m.group(1)))
            # Keep first matching template style
            profile_template = PROFILE_RE.sub("/profile/{id}", path)
            if not profile_template.startswith("/"):
                profile_template = "/" + profile_template
        for hint in ADMIN_HINTS:
            if path.rstrip("/").lower().endswith(hint.rstrip("/")) or hint in path.lower():
                # normalize to path-only
                if url.startswith(base):
                    found_admins.append(path or hint)
                elif path:
                    found_admins.append(path)

    if found_ids:
        probe_ids = sorted(set(found_ids + [max(found_ids) + 1]))
    if found_admins:
        # unique preserve order
        seen: set[str] = set()
        admin_paths = []
        for p in found_admins:
            if p not in seen:
                seen.add(p)
                admin_paths.append(p)
    return profile_template, probe_ids, admin_paths


def check_unauthenticated_access(
    base_url: str,
    *,
    profile_template: str,
    probe_ids: list[int],
    admin_paths: list[str],
) -> ScanResult:
    """Probe IDOR/BAC without credentials when login seeds are unavailable."""
    _validate_local_url(base_url)
    result = ScanResult(module="access_control")
    session = requests.Session()
    requests_sent = 0
    bodies: dict[int, str] = {}

    for pid in probe_ids:
        path = profile_template.format(id=pid)
        if not path.startswith("/"):
            path = "/" + path
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)
            requests_sent += 1
        except requests.RequestException as exc:
            result.errors.append(f"Unauth IDOR probe failed for {url}: {exc}")
            continue
        if resp.status_code == 200 and len(resp.text or "") > 20:
            bodies[pid] = resp.text

    if len(bodies) >= 2:
        ids = sorted(bodies)
        result.findings.append(
            Finding(
                vulnerability_type="Insecure Direct Object Reference",
                title="IDOR: multiple profile IDs readable without authentication",
                url=base_url.rstrip("/") + profile_template.format(id=ids[0]),
                method="GET",
                parameter="user_id",
                input_type="path",
                context="Unauthenticated profile resource access",
                payload_or_probe_id=",".join(str(i) for i in ids),
                evidence={
                    "readable_ids": ids,
                    "response_lengths": {str(i): len(bodies[i]) for i in ids},
                },
                detection_method="authorization_boundary_probe",
                confidence=Confidence.HIGH.value,
                severity=Severity.HIGH.value,
                verification_status=VerificationStatus.PROBABLE.value,
                http_status=200,
                description=(
                    "Multiple user profile resources returned HTTP 200 without an "
                    "authenticated session, indicating missing access control."
                ),
                impact="Attackers can enumerate and read user profile data without logging in.",
                remediation=(
                    "Require authentication and ownership/authorization checks before "
                    "returning object-level profile data."
                ),
                cwe="CWE-639",
                owasp="A01:2025-Broken Access Control",
                module="access_control",
            )
        )

    for admin_path in admin_paths:
        if not admin_path.startswith("/"):
            admin_path = "/" + admin_path
        url = base_url.rstrip("/") + admin_path
        try:
            resp = session.get(url, timeout=5, allow_redirects=False)
            requests_sent += 1
        except requests.RequestException as exc:
            result.errors.append(f"Unauth BAC probe failed for {url}: {exc}")
            continue
        if resp.status_code == 200 and len(resp.text or "") > 20:
            result.findings.append(
                Finding(
                    vulnerability_type="Broken Access Control",
                    title=f"Privileged path {admin_path} reachable without authentication",
                    url=url,
                    method="GET",
                    parameter="",
                    input_type="url",
                    context="Unauthenticated access to a privileged route",
                    payload_or_probe_id="unauthenticated",
                    evidence={
                        "response_status": resp.status_code,
                        "response_length": len(resp.text),
                    },
                    detection_method="authorization_boundary_probe",
                    confidence=Confidence.HIGH.value,
                    severity=Severity.CRITICAL.value,
                    verification_status=VerificationStatus.PROBABLE.value,
                    http_status=resp.status_code,
                    description=(
                        f"{admin_path} returned HTTP 200 without authentication, "
                        "suggesting a missing access-control check."
                    ),
                    impact="Anyone who can reach the host may access privileged functionality.",
                    remediation=(
                        "Require authentication and explicit privilege checks on "
                        "administrative routes."
                    ),
                    cwe="CWE-284",
                    owasp="A01:2025-Broken Access Control",
                    module="access_control",
                )
            )

    result.stats["requests_sent"] = requests_sent
    session.close()
    return result


def check_local_target(
    base_url: str,
    crawl_map: dict[str, Any] | None = None,
    *,
    users: list[tuple[str, str]] | None = None,
    login_path: str = "/login",
) -> ScanResult:
    """Full access-control check against an authorized local target."""
    _validate_local_url(base_url)
    combined = ScanResult(module="access_control")
    profile_template, probe_ids, admin_paths = _discover_from_crawl(base_url, crawl_map)
    users = users or [("alice", "alice123"), ("bob", "bobpass")]

    authenticated = False
    try:
        primary_user, primary_pass = users[0]
        alice_session = login(base_url, primary_user, primary_pass, login_path=login_path)
        if len(users) > 1:
            bob_session = login(base_url, users[1][0], users[1][1], login_path=login_path)
        else:
            bob_session = None
        authenticated = True
    except requests.RequestException as exc:
        combined.errors.append(f"Login failed during access_control setup: {exc}")
        alice_session = None
        bob_session = None

    own_user_id = probe_ids[0] if probe_ids else 1

    if authenticated and alice_session is not None:
        idor_result = check_idor(
            base_url,
            alice_session,
            own_user_id=own_user_id,
            probe_ids=probe_ids,
            profile_template=profile_template,
        )
        combined.findings.extend(idor_result.findings)
        combined.outcomes.extend(idor_result.outcomes)
        combined.errors.extend(idor_result.errors)
        combined.stats["requests_sent"] = (
            combined.stats.get("requests_sent", 0)
            + idor_result.stats.get("requests_sent", 0)
            + len(users)
        )

        for admin_path in admin_paths:
            bac_result = check_broken_access_control(
                base_url, alice_session, admin_path=admin_path
            )
            combined.findings.extend(bac_result.findings)
            combined.outcomes.extend(bac_result.outcomes)
            combined.errors.extend(bac_result.errors)
            combined.stats["requests_sent"] = (
                combined.stats.get("requests_sent", 0)
                + bac_result.stats.get("requests_sent", 0)
            )
        if bob_session is not None:
            bob_session.close()
        alice_session.close()

    # Always run unauthenticated probes as a fallback / supplement for BYO labs.
    unauth = check_unauthenticated_access(
        base_url,
        profile_template=profile_template,
        probe_ids=probe_ids,
        admin_paths=admin_paths,
    )
    # Avoid duplicating the exact same URL+title pairs.
    existing = set()
    for f in combined.findings:
        if hasattr(f, "url") and hasattr(f, "title"):
            existing.add((f.url, f.title))
    for finding in unauth.findings:
        key = (getattr(finding, "url", None), getattr(finding, "title", None))
        if key[0] is None or key not in existing:
            combined.findings.append(finding)
            if key[0] is not None:
                existing.add(key)
    combined.outcomes.extend(unauth.outcomes)
    combined.errors.extend(unauth.errors)
    combined.stats["requests_sent"] = (
        combined.stats.get("requests_sent", 0) + unauth.stats.get("requests_sent", 0)
    )

    if crawl_map is None:
        combined.limitations.append(
            "No crawl map supplied; used default /profile/{id} and /admin paths."
        )
    return combined
