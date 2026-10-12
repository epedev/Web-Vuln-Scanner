"""CLI smoke tests (no network scan)."""

from __future__ import annotations

from pathlib import Path

from vulnsight.cli import main


def test_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip()


def test_doctor(capsys):
    code = main(["--no-color", "doctor"])
    out = capsys.readouterr().out
    assert "V U L N S I G H T" in out
    assert "RESULT: ready" in out or "RESULT: not ready" in out
    assert code in (0, 1)


def test_validate_sample_crawl_map():
    sample = (
        Path(__file__).resolve().parents[2]
        / "xss_module"
        / "fixtures"
        / "sample_crawl_map.json"
    )
    assert sample.is_file()
    assert main(["validate-input", "--file", str(sample)]) == 0


def test_docs_no_open(capsys):
    assert main(["docs", "--no-open"]) == 0
    out = capsys.readouterr().out
    assert "index.html" in out
