"""Orchestrator honesty when a module fails."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from vulnsight.config import ScanConfig
from vulnsight.orchestrator import MODULE_STATUS_FAILED, run_scan
from scanner.models import Finding, ScanResult, Confidence, Severity, VerificationStatus


def _dummy_finding(module: str) -> Finding:
    return Finding(
        vulnerability_type="test",
        title="t",
        url="http://127.0.0.1:5001/x",
        method="GET",
        parameter="q",
        input_type="query",
        context="t",
        payload_or_probe_id="p",
        evidence={},
        detection_method="t",
        confidence=Confidence.LOW.value,
        severity=Severity.LOW.value,
        verification_status=VerificationStatus.CANDIDATE.value,
        http_status=200,
        description="d",
        impact="i",
        remediation="r",
        module=module,
    )


def test_partial_failure_preserves_other_findings(tmp_path):
    sqli_ok = ScanResult(module="sqli", findings=[_dummy_finding("sqli")])
    cmd_ok = ScanResult(module="command_injection", findings=[_dummy_finding("command_injection")])
    ac_ok = ScanResult(module="access_control", findings=[])

    cfg = ScanConfig(
        target="http://127.0.0.1:5001",
        output_dir=str(tmp_path / "out"),
        modules=["sqli", "command_injection", "access_control", "reporting"],
        skip_recon=True,
    )

    with (
        patch("sqli.detector.check_local_target", return_value=sqli_ok),
        patch(
            "command_injection.detector.check_local_target",
            side_effect=RuntimeError("boom"),
        ),
        patch("access_control.detector.check_local_target", return_value=ac_ok),
    ):
        # Ensure module paths resolve imports inside run_scan
        result = run_scan(cfg)

    assert result.exit_code == 1
    assert result.incomplete is True
    assert any(r.name == "command_injection" and r.status == MODULE_STATUS_FAILED for r in result.module_runs)
    assert any((f.get("module") == "sqli" or f.get("source_module") == "sqli") for f in result.findings)
    assert (Path(result.output_dir) / "findings_raw.json").is_file()
