"""CVSS v3.1 base scoring using the official metric model via the `cvss` library."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError


REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

VALID_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


@dataclass
class CVSSResult:
    version: str
    vector: str | None
    base_score: float | None
    severity: str | None
    status: str  # scored | unscored | pending_assessment | invalid
    provenance: str
    rationale: str
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cvss_version": self.version,
            "cvss_vector": self.vector,
            "cvss_base_score": self.base_score,
            "cvss_severity": self.severity,
            "cvss_status": self.status,
            "cvss_provenance": self.provenance,
            "rationale": self.rationale,
            "errors": self.errors,
        }


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "None"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10.0:
        return "Critical"
    raise ValueError(f"score out of range: {score}")


def parse_vector(vector: str) -> dict[str, str]:
    vector = vector.strip()
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("vector must start with CVSS:3.1/")
    parts = vector.split("/")[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if not part or ":" not in part:
            raise ValueError(f"malformed metric segment: {part!r}")
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def validate_metrics(metrics: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_METRICS:
        if key not in metrics:
            errors.append(f"missing metric: {key}")
            continue
        if metrics[key] not in VALID_VALUES[key]:
            errors.append(f"invalid {key}={metrics[key]}")
    extras = set(metrics) - set(REQUIRED_METRICS)
    # Allow Temporal/Environmental to be absent; reject unknown base-like keys
    for key in extras:
        if key in {"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}:
            continue
        errors.append(f"unsupported metric: {key}")
    return errors


def build_vector(metrics: dict[str, str]) -> str:
    ordered = "/".join(f"{k}:{metrics[k]}" for k in REQUIRED_METRICS)
    return f"CVSS:3.1/{ordered}"


def score_vector(
    vector: str,
    *,
    provenance: str = "calculated",
    rationale: str = "",
) -> CVSSResult:
    try:
        metrics = parse_vector(vector)
    except ValueError as exc:
        return CVSSResult(
            version="3.1",
            vector=vector,
            base_score=None,
            severity=None,
            status="invalid",
            provenance=provenance,
            rationale=rationale,
            errors=[str(exc)],
        )
    errors = validate_metrics(metrics)
    if errors:
        return CVSSResult(
            version="3.1",
            vector=vector,
            base_score=None,
            severity=None,
            status="invalid",
            provenance=provenance,
            rationale=rationale,
            errors=errors,
        )
    try:
        c = CVSS3(build_vector(metrics))
        base = float(c.scores()[0])
        # Prefer our band mapping for consistency with acceptance criteria
        sev = severity_from_score(base)
        return CVSSResult(
            version="3.1",
            vector=build_vector(metrics),
            base_score=base,
            severity=sev,
            status="scored",
            provenance=provenance,
            rationale=rationale,
            errors=[],
        )
    except (CVSS3MalformedError, Exception) as exc:
        return CVSSResult(
            version="3.1",
            vector=vector,
            base_score=None,
            severity=None,
            status="invalid",
            provenance=provenance,
            rationale=rationale,
            errors=[f"cvss library error: {exc}"],
        )


def score_or_unscored(
    vector: str | None,
    *,
    provenance: str = "none",
    rationale: str = "",
) -> CVSSResult:
    if not vector:
        return CVSSResult(
            version="3.1",
            vector=None,
            base_score=None,
            severity=None,
            status="unscored",
            provenance="none",
            rationale=rationale or "No CVSS vector provided; score withheld.",
            errors=[],
        )
    return score_vector(vector, provenance=provenance, rationale=rationale)


# Evidence-informed default vectors — explicitly analyst_assessed, not claimed objective.
# Selected from typical web conditions; overridden when modules supply a valid vector.
DEFAULT_VECTORS: dict[str, dict[str, str]] = {
    # Reflected XSS, unauthenticated, victim interaction (click crafted link)
    "xss.reflected": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "rationale": (
            "Network-reachable reflected XSS typically requires user interaction; "
            "scope changed (victim browser); limited C/I impact for generic case."
        ),
    },
    "xss.stored": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "rationale": (
            "Stored XSS often requires low privileges to plant content and user "
            "interaction to view; scope changed; limited C/I for generic case."
        ),
    },
    "sqli": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rationale": (
            "Unauthenticated error/auth-bypass SQLi candidate: network, no UI; "
            "high confidentiality/integrity impact potential; availability not assumed."
        ),
    },
    "command_injection": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rationale": (
            "OS command injection can yield full host compromise (C/I/A High)."
        ),
    },
    "misconfiguration": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "rationale": (
            "Generic missing-security-control / info disclosure misconfig: "
            "low confidentiality; escalate only with stronger evidence."
        ),
    },
}


def suggest_vector_for_type(
    vulnerability_type: str,
    *,
    verification_status: str,
    authenticated: bool | None = None,
) -> CVSSResult:
    """Return an analyst-assessed vector suggestion, or pending if unjustified."""
    vtype = vulnerability_type.lower().strip()
    key = None
    if vtype in DEFAULT_VECTORS:
        key = vtype
    elif "stored" in vtype and "xss" in vtype:
        key = "xss.stored"
    elif "xss" in vtype or "cross-site" in vtype:
        key = "xss.reflected"
    elif "sql" in vtype:
        key = "sqli"
    elif "command" in vtype:
        key = "command_injection"
    elif "misconfig" in vtype or "header" in vtype or "security" in vtype:
        key = "misconfiguration"

    if key is None:
        return CVSSResult(
            version="3.1",
            vector=None,
            base_score=None,
            severity=None,
            status="pending_assessment",
            provenance="none",
            rationale="Insufficient evidence to select CVSS metrics.",
            errors=[],
        )

    entry = DEFAULT_VECTORS[key]
    metrics = parse_vector(entry["vector"])
    if authenticated is True and metrics.get("PR") == "N":
        metrics["PR"] = "L"
    if authenticated is False:
        metrics["PR"] = "N"
    # Do not escalate XSS candidates to high-impact blindly
    if key.startswith("xss") and verification_status in {"candidate", "probable"}:
        # Keep suggested vector but mark as analyst_assessed provisional
        pass

    vector = build_vector(metrics)
    result = score_vector(
        vector,
        provenance="analyst_assessed",
        rationale=entry["rationale"]
        + " Marked analyst_assessed; not claimed as objectively measured.",
    )
    return result
