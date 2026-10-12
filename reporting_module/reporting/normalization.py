"""Normalize module-specific findings into CanonicalFinding records."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from reporting.classification import default_classification, validate_classification
from reporting.cvss import score_or_unscored, suggest_vector_for_type
from reporting.ingestion import LoadedBundle
from reporting.redaction import redact_mapping, redact_text
from reporting.remediation import remediation_for
from reporting.schema import (
    ALLOWED_CONFIDENCE,
    ALLOWED_METHODS,
    ALLOWED_SEVERITIES,
    ALLOWED_VERIFICATION,
    CanonicalFinding,
    ValidationIssue,
    utc_now_iso,
)


def normalize_bundle(
    bundle: LoadedBundle,
    *,
    source_module_override: str | None = None,
    apply_cvss_suggestions: bool = True,
) -> tuple[list[CanonicalFinding], list[ValidationIssue]]:
    findings: list[CanonicalFinding] = []
    issues = list(bundle.issues)
    module_hint = source_module_override or bundle.source_module_hint or "unknown"

    for idx, raw in enumerate(bundle.findings_raw):
        finding, rec_issues = normalize_finding(
            raw,
            source_file=bundle.source_path,
            source_module_hint=module_hint,
            record_index=idx,
            apply_cvss_suggestions=apply_cvss_suggestions,
        )
        issues.extend(rec_issues)
        if finding is not None:
            findings.append(finding)
    return findings, issues


def normalize_finding(
    raw: dict[str, Any],
    *,
    source_file: str,
    source_module_hint: str,
    record_index: int | None = None,
    apply_cvss_suggestions: bool = True,
) -> tuple[CanonicalFinding | None, list[ValidationIssue]]:
    issues: list[ValidationIssue] = []

    def err(msg: str) -> None:
        issues.append(
            ValidationIssue("error", source_file, msg, record_index=record_index)
        )

    def warn(msg: str) -> None:
        issues.append(
            ValidationIssue("warning", source_file, msg, record_index=record_index)
        )

    if not isinstance(raw, dict):
        err("finding is not an object")
        return None, issues

    title = raw.get("title")
    vtype = raw.get("vulnerability_type") or raw.get("type")
    url = raw.get("url") or raw.get("endpoint")
    method = (raw.get("method") or "GET").upper()
    description = raw.get("description") or ""
    impact = raw.get("impact") or ""
    remediation = raw.get("remediation") or ""

    missing = [
        name
        for name, val in [
            ("title", title),
            ("vulnerability_type", vtype),
            ("url", url),
        ]
        if not val
    ]
    if missing:
        err(f"missing required fields: {', '.join(missing)}")
        return None, issues

    title = redact_text(str(title))
    vtype = str(vtype)
    url = redact_text(str(url))
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        warn(f"URL may be invalid: {url}")

    if method not in ALLOWED_METHODS:
        err(f"invalid HTTP method: {method}")
        return None, issues

    source_module = str(
        raw.get("source_module") or raw.get("module") or source_module_hint
    ).lower()
    if source_module in {"", "unknown"}:
        warn("source_module unknown")

    confidence = str(raw.get("confidence") or "medium").lower()
    if confidence not in ALLOWED_CONFIDENCE:
        warn(f"unrecognized confidence {confidence!r}; defaulting to medium")
        confidence = "medium"

    verification = str(
        raw.get("verification_status") or raw.get("status") or "unknown"
    ).lower()
    if verification not in ALLOWED_VERIFICATION:
        warn(f"unrecognized verification_status {verification!r}; using unknown")
        verification = "unknown"

    # Never promote XSS verification beyond what the module reported
    if "xss" in vtype.lower() or source_module == "xss":
        if verification == "confirmed" and raw.get("verification_status") != "confirmed":
            verification = str(raw.get("verification_status") or "candidate")
            warn("refused to promote XSS verification_status to confirmed")

    module_severity = str(raw.get("severity") or "info").lower()
    if module_severity not in ALLOWED_SEVERITIES:
        warn(f"unrecognized module severity {module_severity!r}")
        module_severity = "info"

    parameter = raw.get("parameter")
    if parameter is not None:
        parameter = redact_text(str(parameter))
    location = raw.get("location") or raw.get("context") or raw.get("input_type")
    if location is not None:
        location = str(location)

    evidence = raw.get("evidence") or {}
    if not isinstance(evidence, dict):
        warn("evidence is not an object; coercing to wrapper")
        evidence = {"value": evidence}
    evidence = redact_mapping(evidence)

    cwe = raw.get("cwe")
    owasp = raw.get("owasp")
    if not cwe or not owasp:
        d_cwe, d_owasp = default_classification(vtype)
        cwe = cwe or d_cwe
        owasp = owasp or d_owasp
    clas = validate_classification(cwe, owasp, vtype)
    for w in clas.warnings:
        warn(w)
    for e in clas.errors:
        warn(e)  # classification errors as warnings unless strict later
    cwe, owasp = clas.cwe, clas.owasp

    if not remediation:
        remediation = remediation_for(vtype, location)

    references = raw.get("references") or []
    if not isinstance(references, list):
        references = [str(references)]
    references = [redact_text(str(r)) for r in references]

    fid = str(raw.get("id") or "")
    timestamp = str(raw.get("timestamp") or "")

    # CVSS: prefer module-provided vector; else analyst-assessed suggestion
    cvss_vector = raw.get("cvss_vector") or raw.get("cvss")
    cvss_version = raw.get("cvss_version") or "3.1"
    if cvss_vector:
        scored = score_or_unscored(
            str(cvss_vector),
            provenance="module_provided",
            rationale="Vector supplied by source module.",
        )
    elif apply_cvss_suggestions:
        scored = suggest_vector_for_type(
            vtype, verification_status=verification
        )
    else:
        scored = score_or_unscored(
            None, rationale="CVSS suggestions disabled."
        )

    # Reporting severity prefers CVSS severity when scored
    if scored.status == "scored" and scored.severity:
        severity = scored.severity.lower()
        if severity == "none":
            severity = "info"
    else:
        severity = module_severity

    finding = CanonicalFinding(
        id=fid or str(uuid4()),
        title=title,
        vulnerability_type=vtype,
        source_module=source_module,
        url=url,
        method=method,
        parameter=parameter,
        location=location,
        description=redact_text(str(description)),
        evidence=evidence,
        impact=redact_text(str(impact)),
        remediation=redact_text(str(remediation)),
        severity=severity,
        confidence=confidence,
        verification_status=verification,
        cwe=cwe,
        owasp=owasp,
        cvss_version=scored.version if scored.version else cvss_version,
        cvss_vector=scored.vector,
        cvss_base_score=scored.base_score,
        cvss_severity=scored.severity,
        cvss_status=scored.status,
        cvss_provenance=scored.provenance,
        module_severity=module_severity,
        references=references,
        timestamp=timestamp or utc_now_iso(),
        source_ids=[fid] if fid else [],
        source_files=[source_file],
        original=redact_mapping(dict(raw)),
        warnings=[i.message for i in issues if i.level == "warning"],
    )
    if scored.rationale:
        finding.warnings.append(f"cvss: {scored.rationale}")
    return finding, issues
