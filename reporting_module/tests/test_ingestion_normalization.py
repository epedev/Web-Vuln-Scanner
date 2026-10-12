import json
from pathlib import Path

from reporting.engine import run_report_pipeline
from reporting.ingestion import load_json_file
from reporting.normalization import normalize_bundle
from reporting.redaction import redact_mapping

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_valid_xss_fixture():
    bundle = load_json_file(FIXTURES / "findings_xss.json")
    assert bundle.ok
    findings, issues = normalize_bundle(bundle)
    assert len(findings) == 2
    assert all(f.source_module == "xss" for f in findings)
    assert any(f.verification_status == "probable" for f in findings)
    assert any(f.verification_status == "candidate" for f in findings)


def test_valid_sqli_and_misconfig_fixtures():
    for name in ("findings_sqli.json", "findings_misconfig.json"):
        bundle = load_json_file(FIXTURES / name)
        assert bundle.ok
        findings, _ = normalize_bundle(bundle)
        assert findings


def test_empty_findings():
    bundle = load_json_file
    from reporting.ingestion import load_json_object

    b = load_json_object({"module": "xss", "findings": []})
    assert b.ok
    findings, _ = normalize_bundle(b)
    assert findings == []


def test_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    bundle = load_json_file(p)
    assert not bundle.ok
    assert any(i.level == "error" for i in bundle.issues)


def test_missing_required_fields():
    from reporting.ingestion import load_json_object

    b = load_json_object({"findings": [{"title": "x"}]})
    findings, issues = normalize_bundle(b)
    assert findings == []
    assert any("missing required" in i.message for i in issues)


def test_sensitive_redaction_in_evidence():
    data = {"Authorization": "Bearer abc", "ok": "1"}
    out = redact_mapping(data)
    assert out["Authorization"] == "[REDACTED]"
    assert out["ok"] == "1"


def test_xss_not_promoted_to_confirmed():
    from reporting.normalization import normalize_finding

    f, _ = normalize_finding(
        {
            "title": "t",
            "vulnerability_type": "xss.reflected",
            "url": "http://127.0.0.1/x",
            "method": "GET",
            "verification_status": "candidate",
            "confidence": "medium",
            "severity": "low",
            "description": "d",
            "impact": "i",
            "module": "xss",
        },
        source_file="<t>",
        source_module_hint="xss",
    )
    assert f is not None
    assert f.verification_status == "candidate"


def test_pipeline_aggregates_all_fixtures():
    result = run_report_pipeline(
        input_paths=[
            str(FIXTURES / "findings_xss.json"),
            str(FIXTURES / "findings_sqli.json"),
            str(FIXTURES / "findings_misconfig.json"),
        ],
        modules_executed=["xss", "sqli", "misconfig"],
        modules_not_executed=["command_injection"],
    )
    assert result.summary["total_unique_findings"] >= 5
    # CSP duplicate should collapse
    csp = [
        f
        for f in result.findings
        if "Content-Security-Policy" in f.title or f.id.startswith("misc-1")
    ]
    assert len([f for f in result.findings if "Content-Security-Policy" in f.title]) == 1
    assert "command_injection" in result.modules_not_executed
