"""Tests for Phase 5 features: plugin cemetery, dwell-time, snapshot history,
compare + badge subcommands."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch


def run(coro):
    return asyncio.run(coro)


# ============================== dwell-time helper ==============================

def test_dwell_time_note_parses_cve_year():
    from wpsecscan.checks.plugin_cves import _dwell_time_note
    note, yrs = _dwell_time_note("CVE-2020-12345")
    assert yrs is not None and yrs >= 5  # 2020 vs current year ~2026
    assert "Publicly known since CVE-2020" in note


def test_dwell_time_note_handles_current_year():
    from wpsecscan.checks.plugin_cves import _dwell_time_note
    from datetime import datetime as _dt, timezone as _tz
    note, yrs = _dwell_time_note(f"CVE-{_dt.now(_tz.utc).year}-9999")
    assert yrs == 0
    assert "this year" in note


def test_dwell_time_note_returns_empty_on_unparseable():
    from wpsecscan.checks.plugin_cves import _dwell_time_note
    assert _dwell_time_note("") == ("", None)
    assert _dwell_time_note("not-a-cve") == ("", None)
    assert _dwell_time_note(None) == ("", None)


# ============================== snapshot history ==============================

def test_snapshot_history_returns_timestamped_files_sorted(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import history as _h
    # Two snapshots in chronological order
    _h.save_report_snapshot("https://example.com", '{"target":"x","summary":{}}')
    import time as _t
    _t.sleep(1.05)  # ensure distinct ts strings
    _h.save_report_snapshot("https://example.com", '{"target":"x","summary":{"critical":1}}')
    snaps = _h.snapshot_history("https://example.com")
    assert len(snaps) == 2
    assert snaps[0].stat().st_mtime <= snaps[1].stat().st_mtime
    # The "canonical" file ({safe}.json) is excluded from history
    canonical = tmp_path / "reports" / "example.com.json"
    assert canonical.exists()
    assert canonical not in snaps


# ============================== plugin cemetery ==============================

def test_plugin_cemetery_flags_long_stale(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    # The `from .plugin_cemetery import check as plugin_cemetery` line in
    # checks/__init__.py shadows the submodule, so we reach it via sys.modules.
    import importlib, sys
    importlib.import_module("wpsecscan.checks.plugin_cemetery")
    pc = sys.modules["wpsecscan.checks.plugin_cemetery"]

    def fake_fetch(slug, timeout=8.0):
        if slug == "abandoned-plugin":
            return {"last_updated": "2020-08-14 11:34am GMT", "active_installs": 1000, "tested": "5.5"}
        if slug == "fresh-plugin":
            from datetime import datetime as _dt, timezone as _tz
            return {"last_updated": _dt.now(_tz.utc).strftime("%Y-%m-%d %I:%M%p GMT"),
                    "active_installs": 50000, "tested": "6.4"}
        return None

    # _fetch_wporg is now an async wrapper around _fetch_wporg_sync; patch the
    # sync function so our test still gets to control the response shape.
    monkeypatch.setattr(pc, "_fetch_wporg_sync", fake_fetch)
    ctx = {"target": "https://example.com",
           "shared": {"plugins": {"abandoned-plugin": "1.0", "fresh-plugin": "2.0"}},
           "step": lambda _s: None}
    findings = run(pc.check(None, ctx))  # client is unused in this path
    titles = [f.title for f in findings]
    assert any("abandoned-plugin" in t and ("abandoned" in t or "long-stale" in t)
               for t in titles), titles
    # The fresh plugin must not be flagged
    assert not any("fresh-plugin" in t and ("abandoned" in t or "long-stale" in t)
                   for t in titles), titles


def test_plugin_cemetery_flags_delisted(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    # The `from .plugin_cemetery import check as plugin_cemetery` line in
    # checks/__init__.py shadows the submodule, so we reach it via sys.modules.
    import importlib, sys
    importlib.import_module("wpsecscan.checks.plugin_cemetery")
    pc = sys.modules["wpsecscan.checks.plugin_cemetery"]
    monkeypatch.setattr(pc, "_fetch_wporg_sync", lambda slug, timeout=8.0: {"_delisted": True})
    ctx = {"target": "https://example.com",
           "shared": {"plugins": {"removed-plugin": "1.0"}},
           "step": lambda _s: None}
    findings = run(pc.check(None, ctx))
    assert any("delisted" in f.title for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_plugin_cemetery_skips_plugins_with_cves(monkeypatch, tmp_path):
    """Don't double-report: plugin_cves already fires for these slugs."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    # The `from .plugin_cemetery import check as plugin_cemetery` line in
    # checks/__init__.py shadows the submodule, so we reach it via sys.modules.
    import importlib, sys
    importlib.import_module("wpsecscan.checks.plugin_cemetery")
    pc = sys.modules["wpsecscan.checks.plugin_cemetery"]
    calls = []
    def fake_fetch(slug, timeout=8.0):
        calls.append(slug)
        return {"last_updated": "2020-01-01 11:34am GMT"}
    # _fetch_wporg is now an async wrapper around _fetch_wporg_sync; patch the
    # sync function so our test still gets to control the response shape.
    monkeypatch.setattr(pc, "_fetch_wporg_sync", fake_fetch)
    ctx = {"target": "https://example.com",
           "shared": {"plugins": {"vulnerable-plugin": "1.0"},
                      "cve_matched_slugs": {"vulnerable-plugin"}},
           "step": lambda _s: None}
    findings = run(pc.check(None, ctx))
    assert "vulnerable-plugin" not in calls, "must skip CVE-matched plugins to avoid double-report"
    # And no abandoned-plugin finding emitted
    assert not any("vulnerable-plugin" in (f.title or "") for f in findings
                   if f.severity in ("high", "medium"))


def test_plugin_cemetery_year_parser():
    from wpsecscan.checks.plugin_cemetery import _years_since
    # wp.org typical format
    y = _years_since("2020-01-01 11:34am GMT")
    assert y is not None and y >= 5  # 2020 vs current ~2026
    # ISO
    y2 = _years_since("2024-01-01T00:00:00")
    assert y2 is not None and y2 >= 1
    # Junk
    assert _years_since("") is None
    assert _years_since("not-a-date") is None
