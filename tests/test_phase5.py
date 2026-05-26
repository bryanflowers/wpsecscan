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


# ============================== compare subcommand ==============================

def test_cmd_compare_exits_64_when_no_snapshots(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_compare
    import pytest as _pytest
    with _pytest.raises(SystemExit) as exc:
        _cmd_compare(["https://nonexistent.example.com"])
    assert exc.value.code == 64
    err = capsys.readouterr().err
    assert "found 0" in err or "Need at least 2" in err


def test_cmd_compare_diffs_two_snapshots(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_compare
    from wpsecscan import history as _h
    import time as _time, pytest as _pytest
    # Snapshot 1: clean
    _h.save_report_snapshot("https://x.example.com",
        '{"target":"https://x.example.com","scanned_at":"2026-01-01","results":[]}')
    _time.sleep(1.1)  # distinct timestamp
    # Snapshot 2: has a new finding
    _h.save_report_snapshot("https://x.example.com",
        '{"target":"https://x.example.com","scanned_at":"2026-01-02",'
        '"results":[{"check_name":"sqli","findings":[{"severity":"high","title":"new","url":"u"}]}]}')
    with _pytest.raises(SystemExit) as exc:
        _cmd_compare(["https://x.example.com"])
    # Exit 1 because of the new finding
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "NEW" in out and "new" in out


# ============================== badge subcommand ==============================

def test_cmd_badge_no_snapshot_exits_64(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_badge
    import pytest as _pytest
    with _pytest.raises(SystemExit) as exc:
        _cmd_badge(["https://no-snapshot.example.com"])
    assert exc.value.code == 64


def test_cmd_badge_emits_svg_from_snapshot(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_badge
    from wpsecscan import history as _h
    _h.save_report_snapshot("https://x.example.com",
        '{"target":"https://x.example.com","summary":{"critical":0,"high":1,"medium":2,"low":3,"info":0}}')
    _cmd_badge(["https://x.example.com"])
    out = capsys.readouterr().out
    assert "<svg" in out and "wpsecscan" in out and "high" in out


def test_cmd_badge_writes_to_out_file(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_badge
    from wpsecscan import history as _h
    _h.save_report_snapshot("https://x.example.com",
        '{"target":"https://x.example.com","summary":{"critical":0,"high":0,"medium":0,"low":0,"info":0}}')
    out_file = tmp_path / "badge.svg"
    _cmd_badge(["https://x.example.com", "--out", str(out_file)])
    assert out_file.exists()
    text = out_file.read_text()
    assert "<svg" in text


# ============================== _embed author-leak in users.py =================

def test_users_embed_author_leak_detected():
    """REST _embed exposes author slugs even when /users endpoint is locked."""
    from wpsecscan.checks.users import check
    from tests.conftest import FakeClient, FakeResponse
    import json as _json
    body = _json.dumps([{"id": 1, "title": {"rendered": "Hi"},
                         "_embedded": {"author": [{"id": 1, "slug": "admin"}]}}])
    client = FakeClient(responses={
        "/wp-json/wp/v2/posts?per_page=20&_embed=1": FakeResponse(
            text=body, headers={"content-type": "application/json"}),
    })
    ctx = {"target": "https://x.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("_embed" in f.title and "user(s)" in f.title for f in findings)


def test_users_embed_no_authors_no_finding():
    """If _embedded is missing, the _embed branch must not fire a finding."""
    from wpsecscan.checks.users import check
    from tests.conftest import FakeClient, FakeResponse
    import json as _json
    body = _json.dumps([{"id": 1, "title": {"rendered": "Hi"}}])  # no _embedded
    client = FakeClient(responses={
        "/wp-json/wp/v2/posts?per_page=20&_embed=1": FakeResponse(
            text=body, headers={"content-type": "application/json"}),
    })
    ctx = {"target": "https://x.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert not any("_embed" in f.title for f in findings)


# ============================== --auth-pass - stdin path ============================

def test_auth_pass_stdin_reads_password(monkeypatch):
    """`--auth-pass -` triggers getpass.getpass instead of a literal `-`."""
    from wpsecscan.__main__ import _read_auth_pass_from_stdin
    captured = {}
    def fake_getpass(prompt=""):
        captured["prompt"] = prompt
        return "s3cret-from-stdin"
    monkeypatch.setattr("getpass.getpass", fake_getpass)
    assert _read_auth_pass_from_stdin() == "s3cret-from-stdin"
    assert "prompt" in captured


def test_auth_pass_stdin_aborts_on_eof(monkeypatch, capsys):
    """EOFError from getpass exits 130 with a helpful message."""
    from wpsecscan.__main__ import _read_auth_pass_from_stdin
    def raises_eof(prompt=""): raise EOFError
    monkeypatch.setattr("getpass.getpass", raises_eof)
    import pytest as _pytest
    with _pytest.raises(SystemExit) as exc:
        _read_auth_pass_from_stdin()
    assert exc.value.code == 130
    assert "aborted" in capsys.readouterr().err.lower()


# ============================== Notion export (FEAT-003) =========================

def test_notion_payloads_shape():
    """notion_payloads emits Notion-API page-create dicts with a title in the
    configured title property + per-finding markdown body."""
    from wpsecscan.reporters.issue_export import notion_payloads
    from wpsecscan.models import Finding, CheckResult, ScanReport
    r = ScanReport(
        target="https://x.com", scanned_at="2026-01-01T00:00:00Z", duration_ms=1,
        results=[CheckResult(check_id="sqli", check_name="SQLi", findings=[
            Finding(severity="critical", title="Crit One", evidence="ev1", remediation="fix1"),
            Finding(severity="high",     title="High One", evidence="ev2", remediation="fix2"),
            Finding(severity="low",      title="Low One",  evidence="ev3"),  # below threshold
        ])],
    )
    payloads = notion_payloads(r, "abc123-database-id", title_property="Finding", min_sev="medium")
    assert len(payloads) == 2
    assert payloads[0]["parent"] == {"database_id": "abc123-database-id"}
    assert "Finding" in payloads[0]["properties"]
    title_text = payloads[0]["properties"]["Finding"]["title"][0]["text"]["content"]
    assert "CRITICAL" in title_text and "Crit One" in title_text
    assert payloads[0]["children"][0]["type"] == "paragraph"


def test_notion_curl_commands_use_bearer_token():
    """Token must come from $NOTION_TOKEN, never embedded literally."""
    from wpsecscan.reporters.issue_export import notion_curl_commands
    from wpsecscan.models import Finding, CheckResult, ScanReport
    r = ScanReport(
        target="https://x.com", scanned_at="2026-01-01", duration_ms=1,
        results=[CheckResult(check_id="x", check_name="x",
                             findings=[Finding(severity="high", title="t", evidence="e")])],
    )
    cmds = notion_curl_commands(r, "db-id")
    assert len(cmds) == 1
    assert "Bearer $NOTION_TOKEN" in cmds[0]
    assert "api.notion.com/v1/pages" in cmds[0]
    assert "Notion-Version" in cmds[0]


# ============================== #28 `wpsecscan watch` ==========================

def test_cmd_watch_help_exits_zero(capsys):
    """`wpsecscan watch --help` prints usage and exits 0."""
    from wpsecscan.__main__ import _cmd_watch
    import pytest
    with pytest.raises(SystemExit) as ei:
        _cmd_watch(["--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "watch URL" in out


# ============================== #29 / #30 / #31 ================================

def test_cmd_refix_unknown_check_id_exits_two(capsys):
    """`wpsecscan refix bad_id https://x` exits 2 with a helpful error."""
    from wpsecscan.__main__ import _cmd_refix
    import pytest
    with pytest.raises(SystemExit) as ei:
        _cmd_refix(["wpsecscan_completely_unknown_check_id_xyz", "https://example.com"])
    assert ei.value.code == 2


def test_cmd_portfolio_no_sites_exits_two(monkeypatch, capsys):
    """`wpsecscan portfolio` with no sites exits 2 cleanly."""
    from wpsecscan.__main__ import _cmd_portfolio
    monkeypatch.setattr("wpsecscan.sites.list_sites", lambda: [])
    import pytest
    with pytest.raises(SystemExit) as ei:
        _cmd_portfolio([])
    assert ei.value.code == 2


def test_cmd_snooze_list_empty(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_snooze
    _cmd_snooze(["list"])
    out = capsys.readouterr().out
    assert "no annotations" in out


def test_cmd_snooze_import_csv(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    csv_file = tmp_path / "in.csv"
    csv_file.write_text(
        "url,check_id,finding_title,status,snooze_until,note\n"
        "https://x.com,headers,Missing CSP,accepted-risk,2026-12-31,reviewed by SecOps\n"
        "https://x.com,cors,Wildcard CORS,false-positive,,plugin handles it\n",
        encoding="utf-8",
    )
    from wpsecscan.__main__ import _cmd_snooze
    _cmd_snooze(["import", str(csv_file)])
    from wpsecscan.history import load_annotations
    d = load_annotations()
    assert "https://x.com" in d
    assert len(d["https://x.com"]) == 2


def test_sites_add_persists_tags(monkeypatch, tmp_path):
    """site_mod.add(..., tags=[...]) normalises + stores tags."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import sites as sites_mod
    e = sites_mod.add("https://example.com", tags=["Client:Acme", "tier:gold", "tier:gold"])
    assert e["tags"] == ["client:acme", "tier:gold"]
    # Re-load and re-fetch
    sites = sites_mod.list_sites()
    assert sites[0]["tags"] == ["client:acme", "tier:gold"]


# ============================== FEAT-010 --ai-explain-for ======================

def test_client_summarize_report_attaches_extra(monkeypatch):
    """client_summarize_report attaches extra['client_summary'] to high+critical
    findings only, calls LLM the right number of times, ignores low/medium."""
    from wpsecscan import ai_assist
    from wpsecscan.models import Finding, CheckResult, ScanReport
    monkeypatch.setattr(ai_assist, "is_configured", lambda: True)
    calls = []
    def fake_llm(prompt, *, system="", max_tokens=600):
        calls.append((prompt[:30], system[:20]))
        return "Plain-English explanation."
    monkeypatch.setattr(ai_assist, "llm", fake_llm)
    r = ScanReport(
        target="https://x.com", scanned_at="2026-01-01", duration_ms=1,
        results=[CheckResult(check_id="x", check_name="x", findings=[
            Finding(severity="critical", title="C1", evidence="e", remediation="r"),
            Finding(severity="high",     title="H1", evidence="e", remediation="r"),
            Finding(severity="medium",   title="M1", evidence="e", remediation="r"),
            Finding(severity="low",      title="L1", evidence="e"),
        ])],
    )
    n = ai_assist.client_summarize_report(r, audience="client")
    assert n == 2
    assert len(calls) == 2
    titles = {f.title: f.extra.get("client_summary") for r2 in r.results for f in r2.findings}
    assert titles["C1"] == "Plain-English explanation."
    assert titles["H1"] == "Plain-English explanation."
    assert titles.get("M1") is None
    assert titles.get("L1") is None


def test_client_summarize_report_no_llm_returns_zero(monkeypatch):
    from wpsecscan import ai_assist
    from wpsecscan.models import Finding, CheckResult, ScanReport
    monkeypatch.setattr(ai_assist, "is_configured", lambda: False)
    r = ScanReport(
        target="https://x.com", scanned_at="2026-01-01", duration_ms=1,
        results=[CheckResult(check_id="x", check_name="x",
                             findings=[Finding(severity="critical", title="C", evidence="e")])],
    )
    assert ai_assist.client_summarize_report(r, audience="client") == 0


def test_csv_reporter_adds_client_summary_column_when_present():
    """csv_out adds a client_summary column only when at least one finding has one."""
    from wpsecscan.reporters import csv_out
    from wpsecscan.models import Finding, CheckResult, ScanReport
    base = ScanReport(
        target="https://x.com", scanned_at="2026-01-01", duration_ms=1,
        results=[CheckResult(check_id="x", check_name="x",
                             findings=[Finding(severity="high", title="t")])],
    )
    text_no = csv_out.render(base)
    assert "client_summary" not in text_no.splitlines()[0]
    base.results[0].findings[0].extra["client_summary"] = "Plain words for the client."
    text_yes = csv_out.render(base)
    header = text_yes.splitlines()[0]
    assert "client_summary" in header
    assert "Plain words for the client." in text_yes


def test_markdown_reporter_renders_client_summary():
    from wpsecscan.reporters import markdown as md
    from wpsecscan.models import Finding, CheckResult, ScanReport
    f = Finding(severity="critical", title="t", evidence="e", remediation="r")
    f.extra["client_summary"] = "Your checkout could be down for hours."
    f.extra["client_summary_audience"] = "client"
    r = ScanReport(target="x", scanned_at="2026-01-01", duration_ms=1,
                    results=[CheckResult(check_id="x", check_name="x", findings=[f])])
    text = md.render(r)
    assert "**Plain-English (client)**" in text
    assert "> Your checkout could be down for hours." in text


# ============================== _parse_rdap_expiry ==============================

def test_parse_rdap_expiry_high_severity_under_30d():
    """The full _whois_expiry_finding pipeline emits 'high' < 30 days."""
    from wpsecscan.checks.dns_security import _parse_rdap_expiry
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _, days = _parse_rdap_expiry({"events": [{"eventAction": "expiration", "eventDate": future}]})
    assert days is not None
    assert 0 < days < 30
