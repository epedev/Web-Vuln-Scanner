"""Severity ranking and operational priority (separate from CVSS)."""

from __future__ import annotations

from reporting.owasp_top10 import build_owasp_coverage
from reporting.schema import CanonicalFinding

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
}

VERIFICATION_RANK = {
    "confirmed": 5,
    "probable": 4,
    "candidate": 3,
    "inconclusive": 2,
    "failed": 1,
    "unknown": 1,
    "not_attempted": 0,
    "not_applicable": 0,
    "rejected_safe": 0,
}


def operational_priority(finding: CanonicalFinding) -> str:
    """Documented non-CVSS priority combining score, verification, and confidence."""
    score = finding.cvss_base_score
    ver = finding.verification_status
    if ver == "confirmed" and score is not None and score >= 7.0:
        return "immediate"
    if ver in {"confirmed", "probable"} and score is not None and score >= 4.0:
        return "high"
    if ver == "candidate":
        return "investigate"
    if finding.cvss_status in {"unscored", "pending_assessment", "invalid"}:
        return "needs_assessment"
    if score is not None and score == 0.0:
        return "informational"
    return "planned"


def apply_operational_priority(findings: list[CanonicalFinding]) -> None:
    for f in findings:
        f.operational_priority = operational_priority(f)


def sort_findings(findings: list[CanonicalFinding]) -> list[CanonicalFinding]:
    def key(f: CanonicalFinding):
        sev = SEVERITY_RANK.get(f.severity, 0)
        score = f.cvss_base_score if f.cvss_base_score is not None else -1.0
        ver = VERIFICATION_RANK.get(f.verification_status, 0)
        # unscored after scored peers of same severity
        scored_flag = 1 if f.cvss_base_score is not None else 0
        return (-sev, -scored_flag, -score, -ver, f.url, f.parameter or "", f.id)

    return sorted(findings, key=key)


def build_summary(findings: list[CanonicalFinding]) -> dict:
    by_severity: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    by_module: dict[str, int] = {}
    scores = [f.cvss_base_score for f in findings if f.cvss_base_score is not None]
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_verification[f.verification_status] = (
            by_verification.get(f.verification_status, 0) + 1
        )
        by_module[f.source_module] = by_module.get(f.source_module, 0) + 1

    confirmed = by_verification.get("confirmed", 0)
    probable = by_verification.get("probable", 0)
    candidates = by_verification.get("candidate", 0)

    observations = []
    if not findings:
        observations.append(
            "No findings were reported for the modules that ran. Absence of findings "
            "is not proof that the target is secure; coverage may be incomplete."
        )
    if confirmed:
        observations.append(f"{confirmed} confirmed finding(s) require priority remediation.")
    if probable:
        observations.append(f"{probable} probable finding(s) warrant validation and fix planning.")
    if candidates:
        observations.append(
            f"{candidates} candidate finding(s) should not be treated as confirmed exploits."
        )
    if findings and any(f.cvss_status != "scored" for f in findings):
        observations.append(
            "Some findings lack a complete CVSS vector and remain unscored/pending assessment."
        )

    return {
        "total_unique_findings": len(findings),
        "by_severity": by_severity,
        "by_verification_status": by_verification,
        "by_source_module": by_module,
        "highest_cvss_score": max(scores) if scores else None,
        "scored_findings": len(scores),
        "unscored_findings": sum(1 for f in findings if f.cvss_base_score is None),
        "major_observations": observations,
        "owasp_top10": build_owasp_coverage(findings),
        "remediation_priorities": {
            "immediate": sum(1 for f in findings if f.operational_priority == "immediate"),
            "high": sum(1 for f in findings if f.operational_priority == "high"),
            "investigate": sum(1 for f in findings if f.operational_priority == "investigate"),
            "needs_assessment": sum(
                1 for f in findings if f.operational_priority == "needs_assessment"
            ),
            "planned": sum(1 for f in findings if f.operational_priority == "planned"),
            "informational": sum(
                1 for f in findings if f.operational_priority == "informational"
            ),
        },
    }
