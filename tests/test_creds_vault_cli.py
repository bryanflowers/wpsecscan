"""Wave 3 — tests for the creds_vault module's public API.

The fallback storage path runs whenever keyring is unavailable or its
backend is FailBackend. We monkeypatch `_have_keyring` to force the
fallback path so the test is hermetic on any host.
"""
import json
from pathlib import Path

import pytest

from wpsecscan import creds_vault


@pytest.fixture(autouse=True)
def force_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.setattr(creds_vault, "_have_keyring", lambda: False)
    yield


def test_set_get_round_trip():
    creds_vault.set_secret("https://example.com", "username", "admin")
    creds_vault.set_secret("https://example.com", "password", "s3cret!")
    assert creds_vault.get_secret("https://example.com", "username") == "admin"
    assert creds_vault.get_secret("https://example.com", "password") == "s3cret!"


def test_missing_secret_returns_none():
    assert creds_vault.get_secret("https://nope", "username") is None


def test_delete_secret():
    creds_vault.set_secret("https://x", "field", "value")
    assert creds_vault.delete_secret("https://x", "field") is True
    assert creds_vault.get_secret("https://x", "field") is None


def test_list_sites_after_set():
    creds_vault.set_secret("https://a", "username", "u")
    creds_vault.set_secret("https://b", "password", "p")
    sites = dict(creds_vault.list_sites())
    assert sites["https://a"] == ["username"]
    assert sites["https://b"] == ["password"]


def test_list_fields_for():
    creds_vault.set_secret("https://x", "username", "u")
    creds_vault.set_secret("https://x", "password", "p")
    fields = creds_vault.list_fields_for("https://x")
    assert set(fields) == {"username", "password"}


def test_rotate_overwrites():
    creds_vault.set_secret("https://x", "password", "old")
    creds_vault.rotate_secret("https://x", "password", "new")
    assert creds_vault.get_secret("https://x", "password") == "new"


def test_backend_in_use_reports_fallback():
    assert creds_vault.backend_in_use() == "fallback"


def test_fallback_file_mode_posix(tmp_path):
    """On POSIX, the fallback vault file should be 0600 from creation."""
    import os
    creds_vault.set_secret("https://x", "username", "u")
    p = tmp_path / "creds-vault.json"
    assert p.exists()
    if os.name != "nt":
        mode = p.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_multi_account_via_field_suffix():
    """The CLI encodes multi-account as field@account; vault stores it as-is."""
    creds_vault.set_secret("https://x", "username@admin1", "alice")
    creds_vault.set_secret("https://x", "username@admin2", "bob")
    assert creds_vault.get_secret("https://x", "username@admin1") == "alice"
    assert creds_vault.get_secret("https://x", "username@admin2") == "bob"


def test_delete_removes_from_index():
    creds_vault.set_secret("https://x", "f", "v")
    creds_vault.delete_secret("https://x", "f")
    sites = dict(creds_vault.list_sites())
    assert "https://x" not in sites
