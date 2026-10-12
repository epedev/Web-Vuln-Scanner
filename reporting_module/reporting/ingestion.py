"""JSON loading for module finding files."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reporting.schema import ValidationIssue

SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "1"})


@dataclass
class LoadedBundle:
    source_path: str
    source_module_hint: str | None
    raw: Any
    findings_raw: list[dict[str, Any]] = field(default_factory=list)
    outcomes_raw: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    ok: bool = True


def load_json_file(path: str | Path) -> LoadedBundle:
    path = Path(path)
    bundle = LoadedBundle(source_path=str(path), source_module_hint=None, raw=None)
    if not path.exists():
        bundle.ok = False
        bundle.issues.append(
            ValidationIssue("error", str(path), "file not found")
        )
        return bundle
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        bundle.ok = False
        bundle.issues.append(
            ValidationIssue("error", str(path), f"malformed JSON: {exc}")
        )
        return bundle
    except OSError as exc:
        bundle.ok = False
        bundle.issues.append(
            ValidationIssue("error", str(path), f"read error: {exc}")
        )
        return bundle

    bundle.raw = data
    return _extract_findings(bundle, data)


def load_json_object(
    data: Any,
    *,
    source_path: str = "<memory>",
    source_module_hint: str | None = None,
) -> LoadedBundle:
    bundle = LoadedBundle(
        source_path=source_path,
        source_module_hint=source_module_hint,
        raw=data,
    )
    return _extract_findings(bundle, data)


def _extract_findings(bundle: LoadedBundle, data: Any) -> LoadedBundle:
    if isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, dict):
                bundle.findings_raw.append(item)
            else:
                bundle.issues.append(
                    ValidationIssue(
                        "error",
                        bundle.source_path,
                        f"findings[{i}] is not an object",
                        record_index=i,
                    )
                )
                bundle.ok = False
        return bundle

    if not isinstance(data, dict):
        bundle.ok = False
        bundle.issues.append(
            ValidationIssue(
                "error",
                bundle.source_path,
                "root must be a JSON object or array of findings",
            )
        )
        return bundle

    # Schema version awareness (ScanResult from modules may omit schema_version)
    version = data.get("schema_version")
    if version is not None and str(version) not in SUPPORTED_SCHEMA_VERSIONS:
        if "findings" in data or "module" in data:
            bundle.issues.append(
                ValidationIssue(
                    "warning",
                    bundle.source_path,
                    f"unrecognized schema_version {version!r}; attempting parse",
                )
            )
        else:
            bundle.issues.append(
                ValidationIssue(
                    "error",
                    bundle.source_path,
                    f"unsupported schema version: {version}",
                )
            )
            bundle.ok = False
            return bundle

    if "module" in data and isinstance(data["module"], str):
        bundle.source_module_hint = data["module"]

    if "limitations" in data and isinstance(data["limitations"], list):
        bundle.limitations = [str(x) for x in data["limitations"]]

    if "outcomes" in data and isinstance(data["outcomes"], list):
        for item in data["outcomes"]:
            if isinstance(item, dict):
                bundle.outcomes_raw.append(item)

    if "findings" in data:
        findings = data["findings"]
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            bundle.ok = False
            bundle.issues.append(
                ValidationIssue(
                    "error",
                    bundle.source_path,
                    "'findings' must be an array",
                )
            )
            return bundle
        for i, item in enumerate(findings):
            if isinstance(item, dict):
                bundle.findings_raw.append(item)
            else:
                bundle.ok = False
                bundle.issues.append(
                    ValidationIssue(
                        "error",
                        bundle.source_path,
                        f"findings[{i}] is not an object",
                        record_index=i,
                    )
                )
        return bundle

    # Single finding object heuristic
    if "vulnerability_type" in data or "title" in data:
        bundle.findings_raw.append(data)
        return bundle

    bundle.ok = False
    bundle.issues.append(
        ValidationIssue(
            "error",
            bundle.source_path,
            "no findings array or finding object recognized",
        )
    )
    return bundle
