"""Regression tests for v2.7.1 S1 — marketplace install URL/slug guards.

Before the fix, `wpsecscan marketplace install` accepted any scheme
(file://, http://, ftp://) and any host returned in the index's
source_url. A malicious or MITM'd marketplace index could install
arbitrary Python into ~/.wpsecscan/marketplace/checks/ — RCE on the
next scanner startup.
"""
import pytest

from wpsecscan import marketplace_v27


def test_safe_slug_accepts_normal():
    assert marketplace_v27._safe_slug("my-check") is True
    assert marketplace_v27._safe_slug("my_check") is True
    assert marketplace_v27._safe_slug("MyCheck123") is True


def test_safe_slug_rejects_traversal():
    assert marketplace_v27._safe_slug("../../etc/passwd") is False
    assert marketplace_v27._safe_slug("../evil") is False
    assert marketplace_v27._safe_slug("a/b") is False
    assert marketplace_v27._safe_slug("a\\b") is False


def test_safe_slug_rejects_shell_meta():
    assert marketplace_v27._safe_slug("a;rm -rf") is False
    assert marketplace_v27._safe_slug("a|b") is False
    assert marketplace_v27._safe_slug("a`b") is False
    assert marketplace_v27._safe_slug("a$b") is False
    assert marketplace_v27._safe_slug("") is False  # empty rejected
    assert marketplace_v27._safe_slug("a" * 65) is False  # >64 chars rejected


def test_safe_source_url_rejects_file_scheme():
    ok, reason = marketplace_v27._safe_source_url("file:///etc/passwd")
    assert ok is False
    assert "https" in reason.lower()


def test_safe_source_url_rejects_http():
    ok, reason = marketplace_v27._safe_source_url("http://example.com/x.py")
    assert ok is False
    assert "https" in reason.lower()


def test_safe_source_url_rejects_foreign_host():
    ok, reason = marketplace_v27._safe_source_url(
        "https://attacker.example.com/backdoor.py"
    )
    assert ok is False
    assert "host" in reason.lower() or "origin" in reason.lower()


def test_safe_source_url_accepts_marketplace_origin():
    # Default origin is bryanflowers.github.io
    ok, reason = marketplace_v27._safe_source_url(
        "https://bryanflowers.github.io/wpsecscan/checks/foo.py"
    )
    assert ok is True, reason


def test_safe_source_url_rejects_ftp():
    ok, _ = marketplace_v27._safe_source_url("ftp://example.com/x.py")
    assert ok is False


def test_safe_source_url_rejects_data():
    ok, _ = marketplace_v27._safe_source_url("data:text/plain,hello")
    assert ok is False
