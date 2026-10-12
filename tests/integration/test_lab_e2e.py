"""Optional live integration against an operator-provided authorized lab.

These tests do not ship or start a vulnerable app. Set:

  export VULNSIGHT_LAB_URL=http://127.0.0.1:PORT

to run them against your own prepared local target.
"""

from __future__ import annotations

import os

import pytest
import requests

from vulnsight.config import ScanConfig
from vulnsight.orchestrator import run_scan
from vulnsight.paths import ensure_module_paths

LAB_URL = os.environ.get("VULNSIGHT_LAB_URL", "").rstrip("/")


pytestmark = pytest.mark.skipif(
    not LAB_URL,
    reason="Set VULNSIGHT_LAB_URL to run live tests against your authorized lab",
)


@pytest.fixture(scope="module")
def lab_url():
    try:
        r = requests.get(LAB_URL + "/", timeout=2)
        if r.status_code >= 500:
            pytest.skip(f"lab at {LAB_URL} returned {r.status_code}")
    except requests.RequestException as exc:
        pytest.skip(f"lab not reachable at {LAB_URL}: {exc}")
    return LAB_URL


def test_sqli_cmd_access_against_lab(lab_url):
    ensure_module_paths()
    from access_control.detector import check_local_target as ac
    from command_injection.detector import check_local_target as cmd
    from sqli.detector import check_local_target as sqli

    sqli_r = sqli(lab_url)
    assert isinstance(sqli_r.findings, list)

    cmd_r = cmd(lab_url)
    assert isinstance(cmd_r.findings, list)

    ac_r = ac(lab_url)
    assert isinstance(ac_r.findings, list)


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
    assert result.exit_code in (0, 1)
    assert (out / "findings_raw.json").is_file()
