"""Coverage for wpsecscan/perf_v27.py.

Pins the v2.7.1-era B1 worker URL-validation guard, the etag cache
helpers, the per-check timeout env-var resolution, the prewarm_dns
no-op-on-failure contract, and the parallel scan-zip walker.

Note: payload strings below intentionally use string-concatenation
splits to avoid Windows Defender heuristics that would otherwise quarantine
this test file (e.g. the literal "rm -rf /" or "eval($_POST[...])" trip
ML-based malware classifiers).
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from wpsecscan import perf_v27


# ---------------------------------------------------------------------------
# I110 - cmd_worker URL-validation guard (B1 regression)
# ---------------------------------------------------------------------------

def test_cmd_worker_help_returns_without_error(capsys):
    perf_v27.cmd_worker(["--help"])
    captured = capsys.readouterr()
    assert "wpsecscan worker" in captured.err


def test_cmd_worker_refuses_non_url_queue_entries(monkeypatch, tmp_path, capsys):
    class _Stop(Exception):
        pass

    bad_payloads = [
        b"--config /etc/somefile",
        b"file:///etc/somefile",
        b"-flag-injection-attempt",
    ]

    class _StubPipe:
        def __init__(self):
            self._payloads = list(bad_payloads)

        def brpop(self, queue, timeout=0):  # noqa: ARG002
            if self._payloads:
                return ("k", self._payloads.pop(0))
            raise _Stop()

    class _StubRedisModule:
        @staticmethod
        def from_url(url):  # noqa: ARG004
            return _StubPipe()

    monkeypatch.setitem(__import__("sys").modules, "redis", _StubRedisModule)
    called = []
    with patch("subprocess.run", side_effect=lambda *a, **kw: called.append(a)):
        try:
            perf_v27.cmd_worker(["--queue", "wpsecscan:urls", "--out", str(tmp_path)])
        except _Stop:
            pass
    captured = capsys.readouterr()
    assert "refusing non-URL queue entry" in captured.err
    assert called == [], "subprocess.run must not be called for non-URL targets"


def test_cmd_worker_empty_target_skipped(monkeypatch, tmp_path):
    class _Stop(Exception):
        pass

    class _StubPipe:
        def __init__(self):
            self.calls = 0

        def brpop(self, queue, timeout=0):  # noqa: ARG002
            self.calls += 1
            if self.calls == 1:
                return ("k", b"   ")
            raise _Stop()

    pipe = _StubPipe()

    class _StubRedisModule:
        @staticmethod
        def from_url(url):  # noqa: ARG004
            return pipe

    monkeypatch.setitem(__import__("sys").modules, "redis", _StubRedisModule)
    called = []
    with patch("subprocess.run", side_effect=lambda *a, **kw: called.append(a)):
        with pytest.raises(_Stop):
            perf_v27.cmd_worker(["--out", str(tmp_path)])
    assert called == []


# ---------------------------------------------------------------------------
# I111 - etag cache get/set
# ---------------------------------------------------------------------------

def test_etag_get_returns_none_for_missing_file(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert perf_v27.etag_get("https://example.com") is None


def test_etag_set_then_get_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    perf_v27.etag_set("https://example.com", "etag-abc",
                       "Wed, 21 Oct 2026 07:28:00 GMT")
    got = perf_v27.etag_get("https://example.com")
    assert got == ("etag-abc", "Wed, 21 Oct 2026 07:28:00 GMT")


def test_etag_get_handles_corrupt_db(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    (tmp_path / "etag-cache.json").write_text("not-json")
    assert perf_v27.etag_get("https://example.com") is None


def test_etag_set_handles_corrupt_db(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    (tmp_path / "etag-cache.json").write_text("not-json")
    perf_v27.etag_set("https://example.com", "e", "")
    assert perf_v27.etag_get("https://example.com") == ("e", "")


# ---------------------------------------------------------------------------
# I112 - timeout_for
# ---------------------------------------------------------------------------

def test_timeout_for_specific_env_wins(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_CHECK_TIMEOUT_XMLRPC", "12.5")
    monkeypatch.setenv("WPSECSCAN_DEFAULT_CHECK_TIMEOUT", "60")
    assert perf_v27.timeout_for("xmlrpc") == 12.5


def test_timeout_for_falls_back_to_generic(monkeypatch):
    monkeypatch.delenv("WPSECSCAN_CHECK_TIMEOUT_XMLRPC", raising=False)
    monkeypatch.setenv("WPSECSCAN_DEFAULT_CHECK_TIMEOUT", "45")
    assert perf_v27.timeout_for("xmlrpc") == 45.0


def test_timeout_for_default_when_no_env(monkeypatch):
    monkeypatch.delenv("WPSECSCAN_CHECK_TIMEOUT_XMLRPC", raising=False)
    monkeypatch.delenv("WPSECSCAN_DEFAULT_CHECK_TIMEOUT", raising=False)
    assert perf_v27.timeout_for("xmlrpc") == 30.0
    assert perf_v27.timeout_for("xmlrpc", default=5.0) == 5.0


def test_timeout_for_malformed_env_falls_through(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_CHECK_TIMEOUT_XMLRPC", "not-a-number")
    monkeypatch.setenv("WPSECSCAN_DEFAULT_CHECK_TIMEOUT", "also-bad")
    assert perf_v27.timeout_for("xmlrpc") == 30.0


# ---------------------------------------------------------------------------
# I114 - prewarm_dns
# ---------------------------------------------------------------------------

def test_prewarm_dns_empty_host_returns_false():
    assert asyncio.run(perf_v27.prewarm_dns("")) is False


def test_prewarm_dns_handles_resolution_failure():
    # `.invalid` is reserved (RFC 6761) and never resolves.
    result = asyncio.run(perf_v27.prewarm_dns("this-host-cannot-exist.invalid"))
    assert result is False


# ---------------------------------------------------------------------------
# I115 - scan_zip_parallel_paths
# ---------------------------------------------------------------------------

def test_scan_zip_parallel_paths_finds_matches(tmp_path):
    import re
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    # Defender-safe substrings; we're testing the regex driver, not WordPress.
    a.write_text("PATTERN_A here PATTERN_A again\n")
    b.write_text("just plain text\n")
    patterns = [re.compile(r"PATTERN_A"), re.compile(r"NEVER_MATCHES")]
    hits = perf_v27.scan_zip_parallel_paths([a, b], patterns, workers=2)
    paths = {h[0] for h in hits}
    assert a in paths
    assert b not in paths
    assert any(h[1] == 0 for h in hits)
    assert all(h[1] != 1 for h in hits)


def test_scan_zip_parallel_paths_skips_unreadable(tmp_path):
    import re
    nonexistent = tmp_path / "missing.txt"
    patterns = [re.compile(r"anything")]
    hits = perf_v27.scan_zip_parallel_paths([nonexistent], patterns, workers=1)
    assert hits == []
