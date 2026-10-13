from pathlib import Path

from reporting.classification import normalize_owasp
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
        owasp="A05:2025-Injection",
    )
    base.update(kwargs)
    return CanonicalFinding(**base)


def test_normalize_legacy_2021_to_2025():
    label, warnings, errors = normalize_owasp("A03:2021-Injection")
    assert errors == []
    assert label == "A05:2025-Injection"
    assert any("legacy" in w for w in warnings)

    ssrf, _, errors = normalize_owasp("A10:2021-Server-Side Request Forgery (SSRF)")
    assert errors == []
    assert ssrf == "A01:2025-Broken Access Control"


def test_owasp_coverage_counts_2025_and_legacy():
    cov = build_owasp_coverage(
        [
            _f(owasp="A05:2025-Injection"),
            _f(
                owasp="A01:2025-Broken Access Control",
                cwe="CWE-918",
                source_module="misconfig",
                title="SSRF",
            ),
            _f(
                owasp="A01:2025-Broken Access Control",
                cwe="CWE-639",
                source_module="access_control",
            ),
            _f(
                owasp="A10:2025-Mishandling of Exceptional Conditions",
                cwe="CWE-209",
                source_module="misconfig",
            ),
        ]
    )
    assert cov["standard"] == "OWASP Top 10:2025"
    assert cov["edition_window"] == "2024–2026"
    assert cov["categories_tracked"] == 10
    by_id = {r["id"]: r for r in cov["categories"]}
    assert by_id["A05:2025"]["findings"] == 1
    assert by_id["A01:2025"]["findings"] == 2
    assert by_id["A10:2025"]["findings"] == 1
    assert by_id["A06:2025"]["status"] == "limited_coverage"
    assert by_id["A09:2025"]["status"] == "limited_coverage"
    assert cov["categories_with_findings"] == 3
    legacy = cov["legacy_2021"]
    assert legacy["standard"] == "OWASP Top 10:2021"
    leg = {r["id"]: r for r in legacy["categories"]}
    assert leg["A03:2021"]["findings"] == 1


def test_markdown_includes_owasp_2025_section(tmp_path):
    from reporting.engine import generate_report

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
                "owasp": "A05:2025-Injection",
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
    assert "OWASP Top 10:2025" in md
    assert "A05:2025" in md
    assert "Legacy OWASP Top 10:2021" in md
    assert 'id="owasp-top10"' in html
    assert "OWASP Top 10:2025 coverage" in html
