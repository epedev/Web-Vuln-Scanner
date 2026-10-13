from reporting.owasp_top10 import build_owasp_coverage
from reporting.schema import CanonicalFinding


def _f(**kwargs):
    base = dict(
        id="x",
        title="t",
        vulnerability_type="v",
        severity="medium",
        confidence="high",
        verification_status="candidate",
        url="http://127.0.0.1/",
        method="GET",
        parameter="q",
        description="d",
        impact="i",
        remediation="r",
        evidence={},
        source_module="xss",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
    )
    base.update(kwargs)
    return CanonicalFinding(**base)


def test_owasp_coverage_counts_and_limited():
    cov = build_owasp_coverage(
        [
            _f(owasp="A03:2021-Injection"),
            _f(owasp="A10:2021-Server-Side Request Forgery (SSRF)", cwe="CWE-918", source_module="misconfig"),
            _f(owasp="A01:2021-Broken Access Control", cwe="CWE-639", source_module="access_control"),
        ]
    )
    assert cov["standard"] == "OWASP Top 10:2021"
    assert cov["categories_tracked"] == 10
    by_id = {r["id"]: r for r in cov["categories"]}
    assert by_id["A03:2021"]["findings"] == 1
    assert by_id["A10:2021"]["findings"] == 1
    assert by_id["A01:2021"]["findings"] == 1
    assert by_id["A04:2021"]["status"] == "limited_coverage"
    assert by_id["A09:2021"]["status"] == "limited_coverage"
    assert cov["categories_with_findings"] == 3


def test_markdown_includes_owasp_section(tmp_path):
    from reporting.engine import generate_report
    from pathlib import Path

    result = generate_report(
        output_dir=tmp_path,
        findings_objects=[
            {
                "title": "XSS",
                "vulnerability_type": "Cross-Site Scripting",
                "url": "http://127.0.0.1:5001/r",
                "method": "GET",
                "parameter": "q",
                "severity": "medium",
                "confidence": "high",
                "verification_status": "candidate",
                "description": "d",
                "impact": "i",
                "remediation": "r",
                "cwe": "CWE-79",
                "owasp": "A03:2021-Injection",
                "module": "xss",
                "evidence": {},
            }
        ],
        formats=["html", "md"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    md = Path(result.outputs["md"]).read_text(encoding="utf-8")
    html = Path(result.outputs["html"]).read_text(encoding="utf-8")
    assert "OWASP Top 10:2021" in md
    assert "A03:2021" in md
    assert 'id="owasp-top10"' in html
