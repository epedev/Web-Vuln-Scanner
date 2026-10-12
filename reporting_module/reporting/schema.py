"""Canonical VulnSight finding schema (v1.0)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = "1.0"

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
ALLOWED_SEVERITIES = {"none", "info", "low", "medium", "high", "critical"}
ALLOWED_CONFIDENCE = {"none", "low", "medium", "high", "confirmed"}
ALLOWED_VERIFICATION = {
    "not_applicable",
    "not_attempted",
    "candidate",
    "probable",
    "confirmed",
    "inconclusive",
    "failed",
    "rejected_safe",
    "unknown",
}


@dataclass
class CanonicalFinding:
    """Unified finding used by the reporting engine."""

    title: str
    vulnerability_type: str
    source_module: str
    url: str
    method: str
    description: str
    impact: str
    remediation: str
    severity: str
    confidence: str
    verification_status: str
    id: str = field(default_factory=lambda: str(uuid4()))
    parameter: str | None = None
    location: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    cwe: str | None = None
    owasp: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_status: str = "unscored"  # scored | unscored | pending_assessment | invalid
    cvss_provenance: str = "none"  # calculated | analyst_assessed | module_provided | none
    module_severity: str | None = None
    operational_priority: str | None = None
    references: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    deduplication_key: str = ""
    source_ids: list[str] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    original: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationIssue:
    level: str  # error | warning
    source: str
    message: str
    record_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportResult:
    findings: list[CanonicalFinding]
    issues: list[ValidationIssue]
    summary: dict[str, Any]
    metadata: dict[str, Any]
    limitations: list[str] = field(default_factory=list)
    modules_executed: list[str] = field(default_factory=list)
    modules_not_executed: list[str] = field(default_factory=list)
    incomplete: bool = False
    outputs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "metadata": self.metadata,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "issues": [i.to_dict() for i in self.issues],
            "limitations": self.limitations,
            "modules_executed": self.modules_executed,
            "modules_not_executed": self.modules_not_executed,
            "incomplete": self.incomplete,
            "outputs": self.outputs,
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
