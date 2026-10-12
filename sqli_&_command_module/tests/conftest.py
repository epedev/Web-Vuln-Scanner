
"""Configure imports for tests run from the repository root."""

import sys
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = MODULE_ROOT.parent
XSS_MODELS = REPOSITORY_ROOT / "xss_module"

for path in (str(XSS_MODELS), str(MODULE_ROOT), str(REPOSITORY_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)