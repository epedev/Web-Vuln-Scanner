"""Scan configuration defaults for the VulnSight CLI."""

from __future__ import annotations

from dataclasses import dataclass, field


ALL_MODULES = (
    "recon",
    "xss",
    "sqli",
    "command_injection",
    "access_control",
    "misconfig",
    "reporting",
)


@dataclass
class ScanConfig:
    target: str
    output_dir: str = "reports"
    modules: list[str] = field(default_factory=lambda: list(ALL_MODULES))
    crawl_depth_pages: int = 40
    timeout: float = 10.0
    max_requests: int = 200
    allow_external: bool = False
    allow_loopback: bool = True
    verbose: bool = False
    enable_stored_xss: bool = True
    enable_active_verify: bool = True
    enable_metachar_probes: bool = True
    enable_browser_verify: bool = False
    formats: list[str] = field(default_factory=lambda: ["json", "html", "md", "pdf"])
    crawl_map_path: str | None = None
    skip_recon: bool = False
