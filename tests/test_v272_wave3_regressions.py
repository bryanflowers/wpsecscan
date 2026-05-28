"""Regression tests for v2.7.2 Wave 3 — Medium-severity fixes.

C12 perf_v27.etag_set — atomic temp+replace
C13 continuous_monitor — atomic temp+replace state file
C14 hardware_keys — absolute primary.ctx path (source check)
C15 history — timestamped snapshot written before "latest" promotion
C16 integrations_v27.find_snyk_dups — handles non-dict f.extra
C17 creds_vault index — 0o600 atomic write
"""
import inspect
import json
import os

import pytest


# ---------------------------------------------------------------------------
# C12 — perf_v27.etag_set atomic write
# ---------------------------------------------------------------------------

def test_etag_set_writes_atomically(monkeypatch, tmp_path):
    """Source check: etag_set must use os.replace, not bare write_text."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import perf_v27
    src = inspect.getsource(perf_v27.etag_set)
    assert "os.replace" in src
    # Functional check: still works.
    perf_v27.etag_set("https://example.com", "tag-1", "Wed, 1 Jan 2026 00:00 GMT")
    assert perf_v27.etag_get("https://example.com") == ("tag-1", "Wed, 1 Jan 2026 00:00 GMT")


# ---------------------------------------------------------------------------
# C13 — continuous_monitor atomic state-file write
# ---------------------------------------------------------------------------

def test_continuous_monitor_state_write_is_atomic():
    from wpsecscan import continuous_monitor
    src = inspect.getsource(continuous_monitor)
    # The pre-fix bare `state_file.write_text(json.dumps(new)...)` is gone.
    assert "state_file.write_text(json.dumps(new)" not in src
    # The new pattern is temp + os.replace.
    assert "os.replace" in src and "_tmp" in src


# ---------------------------------------------------------------------------
# C14 — hardware_keys uses absolute primary.ctx path
# ---------------------------------------------------------------------------

def test_hardware_keys_no_bare_primary_ctx_string():
    """The pre-fix code passed the bare literal `"primary.ctx"` AS THE
    subprocess argv slot — relative path, resolved against caller cwd.
    The fix routes it via an absolute Path. We confirm the bug pattern
    (the bare literal occupying an argv slot inside subprocess.run) is
    gone."""
    from wpsecscan import hardware_keys
    src = inspect.getsource(hardware_keys)
    # The bug pattern: "-C", "primary.ctx" (comma between, exact argv).
    assert '"-C", "primary.ctx"' not in src
    assert '"-c", "primary.ctx"' not in src
    # The new pattern uses str(primary_ctx) in those argv slots.
    assert 'str(primary_ctx)' in src


# ---------------------------------------------------------------------------
# C15 — history.save_report writes snapshot before promoting latest
# ---------------------------------------------------------------------------

def test_history_save_report_atomically_promotes_latest():
    from wpsecscan import history
    src = inspect.getsource(history.save_report_snapshot)
    # The new ordering: snap_path.write_text appears BEFORE the os.replace
    # call that promotes "latest".
    snap_pos = src.find("snap_path.write_text")
    latest_pos = src.find("_os.replace(latest_tmp, latest)")
    assert snap_pos >= 0, "snap_path.write_text not found"
    assert latest_pos >= 0, "_os.replace(latest_tmp, latest) not found"
    assert snap_pos < latest_pos, "snapshot must be written BEFORE latest is promoted"


# ---------------------------------------------------------------------------
# C16 — find_snyk_dups handles non-dict f.extra
# ---------------------------------------------------------------------------

def test_import_snyk_findings_handles_non_dict_extra(monkeypatch):
    """A Finding whose `.extra` got overwritten with a non-dict value
    (e.g. JSON null on deserialisation) must not crash the dedup pass
    with TypeError when import_snyk_findings tries to write through
    `f.extra["snyk_dup"] = True`."""
    import httpx as _httpx
    from wpsecscan import integrations_v27
    from wpsecscan.models import Finding, CheckResult, ScanReport

    f_bad = Finding(severity="high", title="t", evidence="e")
    f_bad.extra = None  # type: ignore[assignment]

    cr = CheckResult(check_id="x", check_name="x", findings=[f_bad])
    rep = ScanReport(target="https://t", scanned_at="now", duration_ms=0, results=[cr])

    # Stub httpx.Client so the snyk fetch returns no CVE matches —
    # the contract check (non-dict f.extra rebind) runs regardless of
    # whether any CVE matched.
    class _StubResp:
        status_code = 200
        def json(self):
            return {"data": []}

    class _StubClient:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, *a, **kw): return _StubResp()

    monkeypatch.setattr(_httpx, "Client", _StubClient)
    monkeypatch.setenv("SNYK_TOKEN", "fake")
    monkeypatch.setenv("SNYK_ORG", "fake-org")

    # Must not raise TypeError. The contract fix rebinds f.extra to {}
    # at the top of the per-finding loop so any subsequent write is safe.
    try:
        integrations_v27.import_snyk_findings(rep)
    except TypeError as e:
        pytest.fail(f"import_snyk_findings raised TypeError on non-dict f.extra: {e}")
    assert isinstance(f_bad.extra, dict)


# ---------------------------------------------------------------------------
# C17 — creds_vault index file is 0o600 on POSIX
# ---------------------------------------------------------------------------

def test_creds_vault_index_is_0600_atomic(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import creds_vault
    src = inspect.getsource(creds_vault._save_index)
    assert "0o600" in src
    # Functional: index file mode is restricted on POSIX after a save.
    creds_vault._save_index({"https://t": ["user"]})
    p = creds_vault._index_path()
    assert p.exists()
    if os.name == "posix":
        mode = p.stat().st_mode & 0o777
        assert mode == 0o600
    # Content roundtrip
    assert json.loads(p.read_text(encoding="utf-8")) == {"https://t": ["user"]}
