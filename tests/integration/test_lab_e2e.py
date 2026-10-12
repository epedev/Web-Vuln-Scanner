"""Integration: start target_app and run detection modules against planted vulns."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest
import requests

from vulnsight.config import ScanConfig
from vulnsight.orchestrator import run_scan
from vulnsight.paths import ensure_module_paths


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def lab_url():
    ensure_module_paths()
    from target_app.app import app
    from target_app.database import init_db

    init_db()
    port = _free_port()
    thread = threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1", port=port, debug=False, use_reloader=False
        ),
        daemon=True,
    )
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            r = requests.get(url + "/", timeout=0.5)
            if r.status_code == 200:
                break
        except requests.RequestException:
            time.sleep(0.1)
    else:
        pytest.fail("lab failed to start")
    yield url


def test_sqli_cmd_access_against_lab(lab_url, tmp_path):
    ensure_module_paths()
    from access_control.detector import check_local_target as ac
    from command_injection.detector import check_local_target as cmd
    from sqli.detector import check_local_target as sqli

    sqli_r = sqli(lab_url)
    assert any(f.vulnerability_type == "SQL Injection" for f in sqli_r.findings), sqli_r

    cmd_r = cmd(lab_url)
    assert any(
        f.vulnerability_type == "OS Command Injection" for f in cmd_r.findings
    ), cmd_r
    cmd_finding = next(
        f for f in cmd_r.findings if f.vulnerability_type == "OS Command Injection"
    )
    assert cmd_finding.evidence.get("lab_simulation") is True
    assert cmd_finding.evidence.get("os_shell_executed") is False
    assert cmd_finding.verification_status == "probable"

    ac_r = ac(lab_url)
    types = {f.vulnerability_type for f in ac_r.findings}
    assert "Insecure Direct Object Reference" in types
    assert "Broken Access Control" in types


def test_orchestrator_scan_lab(lab_url, tmp_path):
    out = tmp_path / "reports"
    cfg = ScanConfig(
        target=lab_url,
        output_dir=str(out),
        modules=[
            "recon",
            "xss",
            "sqli",
            "command_injection",
            "access_control",
            "reporting",
        ],
        crawl_depth_pages=25,
        timeout=8.0,
        max_requests=120,
        verbose=False,
        enable_stored_xss=True,
        enable_active_verify=True,
        enable_metachar_probes=True,
    )
    result = run_scan(cfg)
    assert result.exit_code == 0, result.summary_lines()
    types = {f.get("vulnerability_type") for f in result.findings}
    assert "SQL Injection" in types
    assert "OS Command Injection" in types
    assert "Insecure Direct Object Reference" in types
    assert "Broken Access Control" in types
    # XSS module uses types like xss.reflected / xss.stored
    assert any("xss.reflected" == (t or "") for t in types) or any(
        "xss" in (t or "").lower() for t in types
    ), types
    assert "xss.reflected" in types or "xss.stored" in types
    assert (out / "findings.json").is_file() or (out / "normalized_findings.json").is_file()
    assert (out / "vulnsight_report.html").is_file()
    assert (out / "crawl_map.json").is_file()


def test_negative_controls_do_not_bypass_auth(lab_url):
    """Secure login must reject the SQLi comment probe."""
    r = requests.post(
        lab_url + "/login-secure",
        data={"username": "admin' -- ", "password": "x"},
        timeout=5,
        allow_redirects=False,
    )
    assert r.status_code == 200
    assert "Invalid credentials" in r.text


def test_secure_profile_and_admin_deny_cross_access(lab_url):
    s = requests.Session()
    login = s.post(
        lab_url + "/login",
        data={"username": "alice", "password": "alice123"},
        timeout=5,
        allow_redirects=False,
    )
    assert login.status_code in (302, 303)
    denied = s.get(lab_url + "/profile-secure/2", timeout=5, allow_redirects=False)
    assert denied.status_code == 403
    admin = s.get(lab_url + "/admin-secure", timeout=5, allow_redirects=False)
    assert admin.status_code == 403


def test_encoded_xss_control_escapes_markup(lab_url):
    payload = "<script>alert(1)</script>"
    r = requests.get(lab_url + "/encoded", params={"q": payload}, timeout=5)
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
    assert "&#" in r.text or "&lt;script&gt;" in r.text


def test_lab_reset_clears_stored_comments(lab_url):
    from target_app import app as lab_app

    requests.post(lab_url + "/comment", data={"body": "persist-me"}, timeout=5)
    before = requests.get(lab_url + "/comments", timeout=5)
    assert "persist-me" in before.text
    reset = requests.post(lab_url + "/_lab/reset", timeout=5)
    assert reset.status_code == 200
    after = requests.get(lab_url + "/comments", timeout=5)
    assert "persist-me" not in after.text
    # Module-level list should also be empty after reset endpoint
    assert lab_app.COMMENTS == []
