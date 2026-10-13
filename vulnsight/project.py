"""Authorized project file loader for VulnSight scans.

A project file declares the target website under test, explicit authorization,
optional local project path metadata, modules, and scan budgets.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnsight.config import ALL_MODULES, ScanConfig
from vulnsight.scope import LOOPBACK_HOSTS, ScopeError, origin_of, require_lab_target

PROJECT_SCHEMA_VERSION = "1.0"
REQUIRED_AUTH_PHRASE = (
    "I own this system or have explicit written authorization to test it."
)


class ProjectError(Exception):
    """Invalid or unauthorized project configuration."""


@dataclass
class ProjectConfig:
    """Parsed authorized project definition."""

    path: Path
    project_name: str
    target: str
    authorized_origins: list[str]
    authorization_attested: bool
    authorized_by: str
    authorization_notes: str
    project_path: str | None = None
    modules: list[str] = field(default_factory=lambda: list(ALL_MODULES))
    output_dir: str = "reports"
    allow_external: bool = False
    allow_private_network: bool = False
    max_pages: int = 40
    timeout: float = 10.0
    max_requests: int = 200
    crawl_map_path: str | None = None
    enable_stored_xss: bool = True
    enable_active_verify: bool = True
    enable_browser_verify: bool = False
    formats: list[str] = field(default_factory=lambda: ["json", "html", "md", "pdf"])
    raw: dict[str, Any] = field(default_factory=dict)

    def to_scan_config(self, *, verbose: bool = False) -> ScanConfig:
        host = (urlparse(self.target).hostname or "").lower()
        is_loopback = host in LOOPBACK_HOSTS
        # Loopback stays in lab mode; private/public non-loopback needs allow_external.
        allow_external = self.allow_external or (
            self.allow_private_network and not is_loopback
        )
        return ScanConfig(
            target=self.target,
            output_dir=self.output_dir,
            modules=list(self.modules),
            crawl_depth_pages=self.max_pages,
            timeout=self.timeout,
            max_requests=self.max_requests,
            allow_external=allow_external,
            allow_loopback=True,
            verbose=verbose,
            enable_stored_xss=self.enable_stored_xss,
            enable_active_verify=self.enable_active_verify,
            enable_metachar_probes=self.enable_active_verify,
            enable_browser_verify=self.enable_browser_verify,
            formats=list(self.formats),
            crawl_map_path=self.crawl_map_path,
            skip_recon=bool(self.crawl_map_path),
        )


def _is_private_host(hostname: str) -> bool:
    host = hostname.lower()
    if host in LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        # Hostnames like myapp.local are treated as non-loopback; require auth flags.
        return host.endswith(".local") or host.endswith(".lan")


def load_project_file(path: str | Path) -> ProjectConfig:
    """Load and validate an authorized project JSON file."""
    project_path = Path(path).expanduser().resolve()
    if not project_path.is_file():
        raise ProjectError(f"project file not found: {project_path}")

    try:
        data = json.loads(project_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProjectError(f"project file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ProjectError("project file must be a JSON object")

    version = str(data.get("version") or PROJECT_SCHEMA_VERSION)
    if version.split(".")[0] != "1":
        raise ProjectError(f"unsupported project schema version: {version}")

    target = data.get("target")
    if not target or not isinstance(target, str):
        raise ProjectError("project file requires string field 'target'")

    auth = data.get("authorization") or {}
    if not isinstance(auth, dict):
        raise ProjectError("'authorization' must be an object")

    attested = bool(auth.get("i_own_or_have_permission"))
    statement = str(auth.get("statement") or "").strip()
    if not attested:
        raise ProjectError(
            "authorization required: set authorization.i_own_or_have_permission "
            "to true in the project file"
        )
    if statement and statement != REQUIRED_AUTH_PHRASE:
        # Allow missing statement, but if present it must match the required phrase.
        raise ProjectError(
            "authorization.statement must exactly equal:\n"
            f'  "{REQUIRED_AUTH_PHRASE}"'
        )

    authorized_by = str(auth.get("authorized_by") or "").strip()
    if not authorized_by:
        raise ProjectError("authorization.authorized_by is required")

    parsed = urlparse(target.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        raise ProjectError(f"invalid target URL: {target}")

    allow_external = bool(data.get("allow_external", False))
    allow_private = bool(data.get("allow_private_network", False))
    is_loopback = host in LOOPBACK_HOSTS
    is_private = _is_private_host(host)

    if not is_loopback:
        if is_private and not (allow_private or allow_external):
            raise ProjectError(
                "private/local-network target requires "
                "'allow_private_network': true (or allow_external) in the project file"
            )
        if not is_private and not allow_external:
            raise ProjectError(
                "non-loopback public target requires 'allow_external': true "
                "and explicit authorization in the project file"
            )

    # Validate URL shape; loopback uses strict lab rules unless private/external allowed.
    if is_loopback and not allow_external and not allow_private:
        try:
            target_norm = require_lab_target(target, allow_external=False)
        except ScopeError as exc:
            raise ProjectError(str(exc)) from exc
    else:
        try:
            target_norm = require_lab_target(target, allow_external=True)
        except ScopeError as exc:
            raise ProjectError(str(exc)) from exc

    origins = data.get("authorized_origins") or [origin_of(target_norm)]
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        raise ProjectError("authorized_origins must be a list of strings")
    origins = [o.rstrip("/") for o in origins]
    target_origin = origin_of(target_norm)
    if target_origin not in origins and target_norm not in origins:
        # Accept origin match loosely
        if not any(origin_of(o) == target_origin for o in origins):
            raise ProjectError(
                f"target origin {target_origin} is not listed in authorized_origins"
            )

    modules = data.get("modules") or list(ALL_MODULES)
    if modules == "all":
        modules = list(ALL_MODULES)
    if not isinstance(modules, list) or not modules:
        raise ProjectError("modules must be a non-empty list or the string 'all'")
    modules = [str(m).strip() for m in modules]
    unknown = [m for m in modules if m not in ALL_MODULES]
    if unknown:
        raise ProjectError(
            f"unknown modules: {', '.join(unknown)}. "
            f"Allowed: {', '.join(ALL_MODULES)}"
        )

    crawl = data.get("crawl") or {}
    if not isinstance(crawl, dict):
        raise ProjectError("'crawl' must be an object when provided")

    formats = data.get("formats") or ["json", "html", "md", "pdf"]
    if isinstance(formats, str):
        formats = [f.strip() for f in formats.split(",") if f.strip()]
    if not isinstance(formats, list):
        raise ProjectError("formats must be a list or comma-separated string")

    local_project = data.get("project_path")
    if local_project is not None:
        local_project = str(local_project)
        raw_path = Path(local_project).expanduser()
        candidates = []
        if raw_path.is_absolute():
            candidates.append(raw_path)
        else:
            candidates.append((project_path.parent / raw_path).resolve())
            candidates.append((Path.cwd() / raw_path).resolve())
        existing = next((c for c in candidates if c.exists()), None)
        if existing is None:
            raise ProjectError(
                f"project_path does not exist: {local_project} "
                f"(tried: {', '.join(str(c) for c in candidates)})"
            )
        local_project = str(existing)

    output = str(data.get("output") or data.get("output_dir") or "reports")
    if not Path(output).is_absolute():
        output = str((project_path.parent / output).resolve())

    crawl_map = data.get("crawl_map")
    if crawl_map:
        cm = Path(str(crawl_map))
        if not cm.is_absolute():
            cm = project_path.parent / cm
        if not cm.is_file():
            raise ProjectError(f"crawl_map not found: {cm}")
        crawl_map = str(cm.resolve())
    else:
        crawl_map = None

    return ProjectConfig(
        path=project_path,
        project_name=str(data.get("project_name") or project_path.stem),
        target=target_norm,
        authorized_origins=origins,
        authorization_attested=True,
        authorized_by=authorized_by,
        authorization_notes=str(auth.get("notes") or ""),
        project_path=local_project,
        modules=modules,
        output_dir=output,
        allow_external=allow_external,
        allow_private_network=allow_private or allow_external or is_loopback,
        max_pages=int(crawl.get("max_pages") or data.get("max_pages") or 40),
        timeout=float(crawl.get("timeout") or data.get("timeout") or 10.0),
        max_requests=int(data.get("max_requests") or 200),
        crawl_map_path=crawl_map,
        enable_stored_xss=bool(data.get("enable_stored_xss", True)),
        enable_active_verify=bool(data.get("enable_active_verify", True)),
        enable_browser_verify=bool(data.get("enable_browser_verify", False)),
        formats=[str(f) for f in formats],
        raw=data,
    )


def default_project_template(
    *,
    target: str = "http://127.0.0.1:5001",
    project_name: str = "authorized-local-target",
    project_path: str | None = None,
) -> dict[str, Any]:
    """Return a ready-to-edit authorized project template."""
    origin = origin_of(target if "://" in target else f"http://{target}")
    payload: dict[str, Any] = {
        "version": PROJECT_SCHEMA_VERSION,
        "project_name": project_name,
        "target": target.rstrip("/"),
        "authorized_origins": [origin],
        "authorization": {
            "i_own_or_have_permission": True,
            "authorized_by": "REPLACE_WITH_YOUR_NAME",
            "statement": REQUIRED_AUTH_PHRASE,
            "notes": "Local authorized assessment only.",
        },
        "modules": "all",
        "output": "./reports",
        "allow_private_network": True,
        "allow_external": False,
        "formats": ["json", "html", "md", "pdf"],
        "crawl": {"max_pages": 40, "timeout": 10.0},
        "max_requests": 200,
        "enable_stored_xss": True,
        "enable_active_verify": True,
        "enable_browser_verify": False,
    }
    if project_path:
        payload["project_path"] = project_path
    return payload


def write_project_template(
    path: str | Path,
    *,
    target: str = "http://127.0.0.1:5001",
    project_name: str = "authorized-local-target",
    project_path: str | None = None,
) -> Path:
    out = Path(path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    resolved_project_path = None
    if project_path:
        candidate = Path(project_path).expanduser()
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not candidate.exists():
            raise ProjectError(f"project_path does not exist: {candidate}")
        resolved_project_path = str(candidate)
    data = default_project_template(
        target=target,
        project_name=project_name,
        project_path=resolved_project_path,
    )
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return out.resolve()
