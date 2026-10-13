"""Repository path helpers and sys.path bootstrapping for member modules."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

MODULE_DIRS = {
    "crawler": REPO_ROOT / "Crawler",
    "xss": REPO_ROOT / "xss_module",
    "sqli": REPO_ROOT / "sqli_&_command_module",
    "access_control": REPO_ROOT / "access_control_module",
    "reporting": REPO_ROOT / "reporting_module",
    "misconfig": REPO_ROOT / "misconfig_module",
}


def ensure_module_paths() -> None:
    """Add member module directories so their public APIs can be imported."""
    ordered = [
        MODULE_DIRS["xss"],  # shared scanner.models
        MODULE_DIRS["crawler"],
        MODULE_DIRS["sqli"],
        MODULE_DIRS["access_control"],
        MODULE_DIRS["misconfig"],
        MODULE_DIRS["reporting"],
    ]
    for path in ordered:
        text = str(path)
        if path.is_dir() and text not in sys.path:
            sys.path.insert(0, text)
