"""Regression test for v2.7.2 C2 — audit log HMAC compare must be
constant-time.

verify_chain() walked each entry and compared `expected != stored_hmac`
with Python's `!=` operator, which short-circuits on the first differing
byte. An attacker who can append entries to the log and call verify_chain
(directly or via a CLI subcommand) can extract one byte at a time of a
valid HMAC for a tampered prior entry.

The fix is `not hmac.compare_digest(expected, stored_hmac)`.
"""
import inspect

from wpsecscan.auth import audit_log


def test_verify_chain_uses_compare_digest():
    """The verifier must invoke `hmac.compare_digest`, not raw `!=`,
    when comparing the stored HMAC against the recomputed one."""
    src = inspect.getsource(audit_log.verify_chain)
    assert "compare_digest" in src, (
        "verify_chain must compare HMACs via hmac.compare_digest to avoid "
        "a timing side-channel; bare !=/== leaks one byte per comparison."
    )
    # Ensure the old bug-pattern is gone.
    assert "expected != stored_hmac" not in src
    assert "stored_hmac != expected" not in src


def test_verify_chain_still_catches_tampering(tmp_path, monkeypatch):
    """Functional check — after the fix, tampering still surfaces as
    `is_valid == False`."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    audit_log.append("alice", "scan_started", "https://example.com")
    audit_log.append("alice", "scan_finished", "https://example.com")
    ok, n, err = audit_log.verify_chain()
    assert ok is True
    assert n == 2
    assert err == ""

    # Tamper with the first entry's action field.
    log = audit_log._log_path()
    raw = log.read_text(encoding="utf-8")
    tampered = raw.replace('"scan_started"', '"scan_HACKED__"', 1)
    log.write_text(tampered, encoding="utf-8")

    ok, n, err = audit_log.verify_chain()
    assert ok is False
    assert "HMAC mismatch" in err or "mismatch" in err
