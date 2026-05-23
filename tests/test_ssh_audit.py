"""Tests for the SSH wp-cli audit module — uses subprocess mocking."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from wpsecscan.ssh_audit import _validate_ssh_target, audit


def test_validate_rejects_shell_metacharacters():
    for bad in ("user@host; rm -rf /", "user@host`whoami`", "user@host $(id)",
                "user@host && echo pwned", "user @host", "user@host|cat"):
        with pytest.raises(ValueError):
            _validate_ssh_target(bad)


def test_validate_rejects_leading_dash():
    """ssh argument injection — targets starting with - become options."""
    for bad in ("-oProxyCommand=evil", "-J malicious", "-lwheel"):
        with pytest.raises(ValueError, match="may not start with"):
            _validate_ssh_target(bad)


def test_validate_accepts_plain_user_at_host():
    assert _validate_ssh_target("bryan@example.com") == "bryan@example.com"


def test_audit_handles_ssh_not_installed():
    """If subprocess raises FileNotFoundError, audit should report cleanly."""
    with patch("wpsecscan.ssh_audit._ssh_run", return_value=(-2, "", "ssh client not found in PATH")):
        report = audit("bryan@example.com")
    assert any("ssh" in f.evidence.lower() for r in report.results for f in r.findings)


def test_audit_parses_plugin_list():
    """Mock ssh_run to return a plugin-list JSON and verify it's parsed."""
    plugin_json = '[{"name":"wordpress-seo","version":"16.0","status":"active","update":"none"},' \
                  '{"name":"contact-form-7","version":"5.0","status":"active","update":"none"}]'

    def fake_ssh(target, cmd, timeout=20):
        if cmd == ["wp", "--version"]:
            return 0, "WP-CLI 2.9.0", ""
        if cmd == ["wp", "core", "version"]:
            return 0, "6.4.2", ""
        if cmd == ["wp", "plugin", "list", "--format=json"]:
            return 0, plugin_json, ""
        if cmd == ["wp", "theme", "list", "--format=json"]:
            return 0, "[]", ""
        if cmd == ["wp", "user", "list", "--role=administrator", "--format=json"]:
            return 0, "[]", ""
        if cmd[:3] == ["wp", "option", "get"]:
            return 0, "1", ""
        return -1, "", "unknown command"

    with patch("wpsecscan.ssh_audit._ssh_run", side_effect=fake_ssh):
        report = audit("bryan@example.com")

    titles = [f.title for r in report.results for f in r.findings]
    assert any("plugin list" in t.lower() for t in titles)
