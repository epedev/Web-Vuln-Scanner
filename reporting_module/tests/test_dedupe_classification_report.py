from pathlib import Path

from reporting.classification import validate_classification
from reporting.deduplication import deduplicate, make_dedupe_key, normalize_url
from reporting.engine import generate_report, run_report_pipeline
from reporting.schema import CanonicalFinding

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _f(**kwargs):
    base = dict(
        title="t",
        vulnerability_type="xss.reflected",
        source_module="xss",
        url="http://127.0.0.1:5001/reflect?q=1",
        method="GET",
        description="d",
        impact="i",
        remediation="r",
        severity="medium",
        confidence="medium",
        verification_status="candidate",
        parameter="q",
    )
    base.update(kwargs)
    return CanonicalFinding(**base)


def test_exact_duplicates_merge():
    a = _f(id="a", source_ids=["a"], source_files=["1.json"])
    b = _f(id="b", source_ids=["b"], source_files=["2.json"])
    out = deduplicate([a, b])
    assert len(out) == 1
    assert set(out[0].source_ids) == {"a", "b"}


def test_equivalent_url_normalization():
    assert normalize_url("http://HOST/a/?b=1&a=2") == normalize_url(
        "http://host/a?a=2&b=1"
    )


def test_different_parameters_not_merged():
    out = deduplicate([_f(parameter="q"), _f(parameter="x")])
    assert len(out) == 2


def test_different_methods_not_merged():
    out = deduplicate([_f(method="GET"), _f(method="POST")])
    assert len(out) == 2


def test_reflected_vs_stored_not_merged():
    out = deduplicate(
        [
            _f(vulnerability_type="xss.reflected"),
            _f(vulnerability_type="xss.stored"),
        ]
    )
    assert len(out) == 2
    assert make_dedupe_key(out[0]) != make_dedupe_key(out[1])


def test_different_vuln_classes_same_url_not_merged():
    out = deduplicate(
        [
            _f(vulnerability_type="xss.reflected"),
            _f(vulnerability_type="SQL Injection", source_module="sqli"),
        ]
    )
    assert len(out) == 2


def test_csrf_not_classified_as_xss():
    from reporting.deduplication import vulnerability_class

    assert vulnerability_class("Cross-Site Request Forgery") == "csrf"
    assert vulnerability_class("Cross-Site Scripting") == "xss"


def test_distinct_missing_headers_not_merged():
    out = deduplicate(
        [
            _f(
                title="Missing Content-Security-Policy header",
                vulnerability_type="Security Misconfiguration",
                source_module="misconfig",
                parameter="",
                location="HTTP response hygiene",
                evidence={"missing_header": "Content-Security-Policy"},
            ),
            _f(
                title="Missing X-Frame-Options header",
                vulnerability_type="Security Misconfiguration",
                source_module="misconfig",
                parameter="",
                location="HTTP response hygiene",
                evidence={"missing_header": "X-Frame-Options"},
            ),
            _f(
                title="Technology disclosure via Server header",
                vulnerability_type="Security Misconfiguration",
                source_module="misconfig",
                parameter="",
                location="HTTP response hygiene",
                evidence={"header": "Server", "value": "Werkzeug"},
            ),
        ]
    )
    assert len(out) == 3


def test_cwe_owasp_validation():
    ok = validate_classification("CWE-79", "A05:2025-Injection", "xss")
    assert ok.cwe == "CWE-79"
    assert ok.owasp.startswith("A05:2025")
    legacy = validate_classification("CWE-79", "A03:2021-Injection", "xss")
    assert legacy.owasp == "A05:2025-Injection"
    bad = validate_classification("CWE-XX", "A99:2099", "xss")
    assert bad.errors


def test_html_report_escapes_and_counts(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        input_paths=[
            str(FIXTURES / "findings_xss.json"),
            str(FIXTURES / "findings_sqli.json"),
            str(FIXTURES / "findings_misconfig.json"),
        ],
        formats=["html", "json"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
        modules_executed=["xss", "sqli", "misconfig"],
        modules_not_executed=["command_injection"],
    )
    html_path = Path(result.outputs["html"])
    text = html_path.read_text(encoding="utf-8")
    assert "VulnSight" in text
    assert "Executive summary" in text
    assert "super-secret-token" not in text
    assert "[REDACTED]" in text or "Authorization" in text
    assert "<script>alert(1)</script>" not in text  # no raw exec from fixtures
    # XSS-sensitive title injection attempt via crafted finding
    assert result.summary["total_unique_findings"] == len(result.findings)
    assert "command_injection" in result.modules_not_executed


def test_html_escapes_injected_markup(tmp_path):
    from reporting.ingestion import load_json_object
    from reporting.normalization import normalize_bundle
    from reporting.html_report import write_html
    from reporting.risk import apply_operational_priority, build_summary, sort_findings
    from reporting.schema import ReportResult

    bundle = load_json_object(
        {
            "module": "xss",
            "findings": [
                {
                    "title": "<img src=x onerror=alert(1)>",
                    "vulnerability_type": "xss.reflected",
                    "url": "http://127.0.0.1/x",
                    "method": "GET",
                    "description": "<script>alert(1)</script>",
                    "impact": "i",
                    "severity": "low",
                    "confidence": "low",
                    "verification_status": "candidate",
                }
            ],
        }
    )
    findings, _ = normalize_bundle(bundle)
    apply_operational_priority(findings)
    findings = sort_findings(findings)
    result = ReportResult(
        findings=findings,
        issues=[],
        summary=build_summary(findings),
        metadata={
            "product": "VulnSight",
            "report_title": "t",
            "target": "t",
            "authorized_origin": "t",
            "scope": "s",
            "assessment_date": "2026-10-11",
            "generated_at": "2026-10-11T00:00:00+00:00",
            "scan_id": "1",
            "scanner_version": "0.1",
            "schema_version": "1.0",
        },
        limitations=[],
        modules_executed=["xss"],
        modules_not_executed=["sqli"],
    )
    path = write_html(result, tmp_path / "escape.html")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html or "&lt;img" in html


def test_pdf_optional(tmp_path):
    from reporting.pdf_report import weasyprint_available

    result = generate_report(
        output_dir=tmp_path,
        input_paths=[str(FIXTURES / "findings_xss.json")],
        formats=["html", "json"] + (["pdf"] if weasyprint_available() else []),
        pdf=weasyprint_available(),
        modules_executed=["xss"],
        modules_not_executed=["sqli", "misconfig", "command_injection"],
    )
    assert "html" in result.outputs
    if weasyprint_available():
        pdf = Path(result.outputs["pdf"])
        assert pdf.exists() and pdf.stat().st_size > 0
    else:
        # Should not crash without PDF
        assert "pdf" not in result.outputs
