"""Tests for authorized project file loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnsight.project import ProjectError, load_project_file, write_project_template


def test_load_sample_project():
    sample = Path(__file__).resolve().parents[2] / "fixtures" / "sample_project.json"
    cfg = load_project_file(sample)
    assert cfg.target == "http://127.0.0.1:5001"
    assert cfg.authorization_attested is True
    assert "xss" in cfg.modules
    assert "reporting" in cfg.modules
    scan = cfg.to_scan_config()
    assert scan.target.endswith("5001")


def test_rejects_missing_authorization(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "target": "http://127.0.0.1:5001",
                "authorization": {
                    "i_own_or_have_permission": False,
                    "authorized_by": "x",
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProjectError, match="authorization required"):
        load_project_file(path)


def test_init_and_load_roundtrip(tmp_path):
    out = tmp_path / "proj.json"
    write_project_template(out, target="http://127.0.0.1:5001", project_name="demo")
    data = json.loads(out.read_text(encoding="utf-8"))
    data["authorization"]["authorized_by"] = "Tester"
    out.write_text(json.dumps(data), encoding="utf-8")
    cfg = load_project_file(out)
    assert cfg.project_name == "demo"
    assert cfg.authorized_by == "Tester"


def test_private_host_requires_flag(tmp_path):
    path = tmp_path / "lan.json"
    path.write_text(
        json.dumps(
            {
                "target": "http://192.168.1.10:8080",
                "authorized_origins": ["http://192.168.1.10:8080"],
                "authorization": {
                    "i_own_or_have_permission": True,
                    "authorized_by": "Owner",
                },
                "allow_private_network": False,
                "allow_external": False,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProjectError, match="allow_private_network"):
        load_project_file(path)
