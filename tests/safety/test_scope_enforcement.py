"""Safety: CLI must not scan external hosts by default."""

from __future__ import annotations

import pytest

from vulnsight.cli import main


def test_scan_rejects_external_without_flag(capsys):
    code = main(["scan", "--target", "http://example.com", "--output", "/tmp/vs-out"])
    assert code == 2
    err = capsys.readouterr().err
    assert "scope" in err.lower() or "loopback" in err.lower() or "lab" in err.lower()
