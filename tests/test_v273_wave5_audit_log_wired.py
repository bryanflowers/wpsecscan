"""Regression tests for v2.7.3 Wave 5 — audit_log.append wired into
the auth-sensitive production paths.

Before v2.7.3 the audit_log module existed and was unit-tested, but
NO production code ever called it — the audit trail it advertised
didn't exist at runtime. Wave 5 wires it into:
  * creds_vault.set_secret / delete_secret
  * marketplace_v27 install (success + failure) / verify

Note: per the v2.7.3 scope decision, rbac/sso/approval_workflow
wiring is deferred to v2.8.0 RFC.
"""
import json

import pytest


@pytest.fixture
def isolated_home(monkeypatch, tmp_path):
    """Each test gets a clean WPSECSCAN_HOME so the audit log starts empty."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    # Force the keyring backend to "missing" so set_secret goes through
    # the fallback path AND the audit hook fires the same way regardless
    # of the test machine's keyring availability.
    monkeypatch.setattr("wpsecscan.creds_vault._have_keyring", lambda: False)
    return tmp_path


def _audit_lines(home_path):
    """Return parsed audit log entries (most recent last)."""
    p = home_path / "audit.log.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").rstrip().splitlines()]


# ---------------------------------------------------------------------------
# safe_append + default actor
# ---------------------------------------------------------------------------

def test_safe_append_swallows_audit_failures(monkeypatch, tmp_path):
    """An audit-log write failure must NOT propagate to the calling
    operation (a creds_vault.set_secret call must succeed even when
    the audit log is unwriteable)."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.auth import audit_log
    # Patch append to always raise.
    monkeypatch.setattr(audit_log, "append",
                          lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    # Must not raise.
    audit_log.safe_append("test.action", target="x")


def test_default_actor_falls_back_to_wpsecscan_actor_env(monkeypatch):
    from wpsecscan.auth.audit_log import _default_actor
    monkeypatch.setenv("WPSECSCAN_ACTOR", "alice@example.com")
    assert _default_actor() == "alice@example.com"


def test_default_actor_truncates_to_64_chars(monkeypatch):
    from wpsecscan.auth.audit_log import _default_actor
    monkeypatch.setenv("WPSECSCAN_ACTOR", "x" * 200)
    assert len(_default_actor()) == 64


# ---------------------------------------------------------------------------
# creds_vault.set_secret / delete_secret are audited
# ---------------------------------------------------------------------------

def test_creds_set_secret_writes_audit_log_entry(isolated_home):
    from wpsecscan import creds_vault
    creds_vault.set_secret("https://example.com", "wp_admin_password", "hunter2")
    entries = _audit_lines(isolated_home)
    assert len(entries) >= 1
    last = entries[-1]
    assert last["action"] == "creds.set_secret"
    assert last["target"] == "https://example.com::wp_admin_password"
    # The value itself must NOT appear in the audit log.
    assert "hunter2" not in json.dumps(last)
    # The value LENGTH may appear for forensic timeline purposes.
    assert last["details"].get("value_len") == 7


def test_creds_delete_secret_writes_audit_log_entry(isolated_home):
    from wpsecscan import creds_vault
    creds_vault.set_secret("https://t", "f", "v")
    creds_vault.delete_secret("https://t", "f")
    actions = [e["action"] for e in _audit_lines(isolated_home)]
    assert "creds.set_secret" in actions
    assert "creds.delete_secret" in actions


def test_creds_audit_log_chain_verifies(isolated_home):
    """The HMAC chain across the wired audit entries must verify."""
    from wpsecscan import creds_vault
    from wpsecscan.auth import audit_log
    creds_vault.set_secret("https://a", "f1", "v1")
    creds_vault.set_secret("https://b", "f2", "v2")
    creds_vault.delete_secret("https://a", "f1")
    ok, n, err = audit_log.verify_chain()
    assert ok, f"audit chain broken: {err}"
    assert n >= 3
