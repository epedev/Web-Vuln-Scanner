"""Root pytest path bootstrap for VulnSight integration tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
paths = [
    ROOT,
    ROOT / "xss_module",
    ROOT / "Crawler",
    ROOT / "reporting_module",
    ROOT / "sqli_&_command_module",
    ROOT / "access_control_module",
]
for path in paths:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)
