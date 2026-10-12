"""CLI UI theme tests (no TTY required)."""

from __future__ import annotations

from io import StringIO

from vulnsight.ui import Console, color_enabled


def test_no_color_strips_ansi():
    out = StringIO()
    ui = Console(no_color=True, out=out, err=out)
    ui.banner(subtitle="test")
    ui.status_ok("ready")
    text = out.getvalue()
    assert "\033[" not in text
    assert "VULNSIGHT" in text or "V U L N" in text
    assert "ready" in text


def test_color_force_off_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert color_enabled() is False


def test_panel_and_meter_no_color():
    out = StringIO()
    ui = Console(no_color=True, out=out, err=out)
    ui.panel("SCAN BRIEF", [("target", "http://127.0.0.1:5001"), ("scope", "lab")])
    ui.finding_meter(2, 3, 5)
    text = out.getvalue()
    assert "SCAN BRIEF" in text
    assert "confirmed" in text
    assert "intensity" in text
