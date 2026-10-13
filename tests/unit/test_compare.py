
from pathlib import Path
import json

from vulnsight.compare import compare_findings, write_compare_report


def test_compare_detects_new_findings(tmp_path):
    baseline = {"findings": []}
    current = {
        "findings": [
            {
                "title": "Missing CSP",
                "vulnerability_type": "Security Misconfiguration",
                "url": "http://127.0.0.1:5000/",
                "parameter": "",
                "severity": "medium",
                "module": "misconfig",
            }
        ]
    }
    b = tmp_path / "base.json"
    c = tmp_path / "cur.json"
    b.write_text(json.dumps(baseline))
    c.write_text(json.dumps(current))
    result = compare_findings(c, b)
    assert result["summary"]["new_count"] == 1
    paths = write_compare_report(result, tmp_path / "out")
    assert Path(paths["md"]).is_file()
