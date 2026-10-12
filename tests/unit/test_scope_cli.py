"""Unit tests for VulnSight CLI scope helpers."""

from __future__ import annotations

import pytest

from vulnsight.scope import ScopeError, origin_of, require_lab_target


def test_lab_loopback_ok():
    assert require_lab_target("http://127.0.0.1:5001") == "http://127.0.0.1:5001"


def test_lab_localhost_ok():
    assert require_lab_target("http://localhost:5001") == "http://localhost:5001"


def test_lab_ipv6_loopback_ok():
    assert require_lab_target("http://[::1]:5001") == "http://[::1]:5001"


def test_lab_rejects_external_by_default():
    with pytest.raises(ScopeError):
        require_lab_target("http://example.com")


def test_allow_external_permits_remote():
    assert require_lab_target("https://example.com", allow_external=True) == "https://example.com"


def test_rejects_credentials_in_url():
    with pytest.raises(ScopeError):
        require_lab_target("http://user:pass@127.0.0.1:5001")


def test_rejects_https_in_lab_mode():
    with pytest.raises(ScopeError):
        require_lab_target("https://127.0.0.1:5001")


def test_rejects_file_scheme():
    with pytest.raises(ScopeError):
        require_lab_target("file:///etc/passwd")


def test_origin_of_ipv6():
    assert origin_of("http://[::1]:5001/path") == "http://[::1]:5001"
