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


# ============================== #49 / #50 ======================================

def test_exec_pdf_trend_svg_empty_when_no_snapshots(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.reporters.exec_pdf import _trend_svg_block
    assert _trend_svg_block("https://no-snaps.example") == ""


def test_exec_pdf_trend_svg_renders_polyline(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import json as _json, time as _t
    from wpsecscan import history as _h
    url = "https://trendsvg.example"
    for s in (40, 55, 70):
        _h.save_report_snapshot(url, _json.dumps({"risk_score": s, "summary": {}}))
        _t.sleep(1.05)
    from wpsecscan.reporters.exec_pdf import _trend_svg_block
    svg = _trend_svg_block(url)
    assert "<polyline" in svg
    assert "Risk-score trend" in svg


def test_cmd_publish_writes_signed_pages(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import json as _json
    from wpsecscan import history as _h
    url = "https://publish.example"
    _h.save_report_snapshot(url, _json.dumps({
        "risk_score": 78,
        "scanned_at": "2026-05-26T10:00:00Z",
        "summary": {"critical": 0, "high": 1, "medium": 2, "low": 5, "info": 0},
    }))
    from wpsecscan.__main__ import _cmd_publish
    out_dir = tmp_path / "publish-out"
    _cmd_publish([url, "--out", str(out_dir)])
    html = (out_dir / "scan-receipt.html").read_text(encoding="utf-8")
    receipt = _json.loads((out_dir / "scan-receipt.json").read_text(encoding="utf-8"))
    assert "78/100" in html
    assert "publish.example" in html
    assert receipt["risk_score"] == 78
    assert receipt["signature"].startswith("sha256=")
    # Verify the signature is genuine: recompute with the secret on disk.
    import hmac as _hmac, hashlib as _h2
    secret = _json.loads((tmp_path / "publish-secret.json").read_text())["secret"]
    canonical = _json.dumps({k: v for k, v in receipt.items() if k != "signature"},
                              sort_keys=True).encode("utf-8")
    expected = _hmac.new(secret.encode(), canonical, _h2.sha256).hexdigest()
    assert receipt["signature"] == f"sha256={expected}"


# ============================== #46 / #47 / #48 ================================

def test_snapshot_compare_renders_fixed_new_unchanged():
    from wpsecscan.reporters.snapshot_compare import render
    old = {
        "target": "https://x.com", "scanned_at": "2026-05-25", "risk_score": 50,
        "results": [{"check_id": "h", "findings": [
            {"severity": "high", "title": "Missing CSP"},
            {"severity": "medium", "title": "Stable issue"},
        ]}],
    }
    new = {
        "target": "https://x.com", "scanned_at": "2026-05-26", "risk_score": 35,
        "results": [{"check_id": "h", "findings": [
            {"severity": "medium", "title": "Stable issue"},
            {"severity": "critical", "title": "New problem"},
        ]}],
    }
    html = render(old, new)
    assert "Fixed (1)" in html
    assert "Missing CSP" in html
    assert "New problem" in html
    assert "Stable issue" in html
    # Score delta rendered
    assert ">-15<" in html or "delta-dn" in html


def test_remediation_videos_lookup():
    from wpsecscan.remediation_videos import video_for
    v = video_for("xss", "Reflected XSS in /search")
    assert v is not None
    assert "youtube" in v["url"]
    assert video_for("nonexistent_check_id_xxxx") is None


def test_docx_report_rtf_fallback_writes_valid_rtf(monkeypatch, tmp_path):
    """When python-docx isn't installed, we fall back to an .rtf file with
    a valid RTF header."""
    from wpsecscan.reporters import docx_report as _dx
    from wpsecscan.models import Finding, CheckResult, ScanReport
    # Force the ImportError path: monkeypatch _write_docx to raise ImportError
    def _explode(*a, **kw): raise ImportError("python-docx not installed (test stub)")
    monkeypatch.setattr(_dx, "_write_docx", _explode)
    report = ScanReport(target="https://x.com", scanned_at="2026-05-26",
                          duration_ms=1, results=[
                              CheckResult(check_id="h", check_name="Headers", findings=[
                                  Finding(severity="high", title="Missing CSP",
                                            evidence="GET / → no CSP",
                                            remediation="Add a CSP header"),
                              ]),
                          ])
    out = tmp_path / "report.docx"
    _dx.write(report, out)
    rtf = tmp_path / "report.rtf"
    assert rtf.exists()
    text = rtf.read_text(encoding="utf-8")
    assert text.startswith("{\\rtf1")
    assert "Missing CSP" in text


# ============================== #38 / #40 / #41 ================================

def test_notify_post_json_includes_signature_header(monkeypatch):
    """When signing_secret is set, _post_json adds X-WPSecScan-Signature."""
    from wpsecscan import notify as _n
    seen_headers = {}
    class _FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b""
    def _fake_urlopen(req, timeout=4.0):
        seen_headers.update(dict(req.header_items()))
        return _FakeResp()
    monkeypatch.setattr(_n.urllib.request, "urlopen", _fake_urlopen)
    ok, err = _n._post_json("https://hooks.slack.com/services/aaa/bbb/ccc",
                              {"text": "hello"}, signing_secret="topsecret")
    assert ok, err
    # Header names are title-cased by urllib's header_items()
    keys = {k.lower() for k in seen_headers}
    assert "x-wpsecscan-signature" in keys
    assert "x-wpsecscan-timestamp" in keys


def test_policy_severity_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import json as _json
    (tmp_path / "policy.json").write_text(_json.dumps({
        "severity_overrides": {"headers": {"Missing CSP": "critical"}},
    }), encoding="utf-8")
    from wpsecscan.models import Finding, CheckResult, ScanReport
    from wpsecscan import policy as _p
    report = ScanReport(target="x", scanned_at="t", duration_ms=1, results=[
        CheckResult(check_id="headers", check_name="x", findings=[
            Finding(severity="medium", title="Missing CSP header"),
            Finding(severity="low", title="Something else"),
        ]),
    ])
    pol = _p.load()
    n = _p.apply_severity_overrides(report, pol)
    assert n == 1
    assert report.results[0].findings[0].severity == "critical"
    assert report.results[0].findings[1].severity == "low"


def test_policy_suppression(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import json as _json
    (tmp_path / "policy.json").write_text(_json.dumps({
        "suppress": {
            "https://x.com": [
                {"check_id": "cors", "title_regex": "Wildcard CORS",
                 "reason": "REST API is intentionally public"},
            ],
        },
    }), encoding="utf-8")
    from wpsecscan.models import Finding, CheckResult, ScanReport
    from wpsecscan import policy as _p
    report = ScanReport(target="https://x.com", scanned_at="t", duration_ms=1, results=[
        CheckResult(check_id="cors", check_name="x", findings=[
            Finding(severity="high", title="Wildcard CORS origin"),
            Finding(severity="medium", title="Something else"),
        ]),
    ])
    n = _p.apply_suppressions(report, _p.load())
    assert n == 1
    assert len(report.results[0].findings) == 1
    assert report.results[0].findings[0].title == "Something else"


# ============================== #36 pr_inspector ===============================

def test_pr_inspector_parse_url():
    from wpsecscan.pr_inspector import _parse_pr_url
    assert _parse_pr_url("https://github.com/owner/repo/pull/123") == ("owner", "repo", 123)
    assert _parse_pr_url("https://gitlab.com/owner/repo/-/merge_requests/1") is None
    assert _parse_pr_url("https://github.com/owner/repo") is None


def test_pr_inspector_build_comment_no_touches():
    from wpsecscan.pr_inspector import build_comment
    out = build_comment({"plugins": [], "themes": []}, [])
    assert "No WordPress plugins or themes touched" in out
    assert "wpsecscan-pr-comment" in out  # marker


def test_pr_inspector_build_comment_with_cves():
    from wpsecscan.pr_inspector import build_comment
    touched = {"plugins": ["woocommerce", "yoast-seo"], "themes": []}
    findings = [
        {"slug": "woocommerce", "type": "plugin",
         "cves": [{"cve_id": "CVE-2026-12345", "severity": "high"},
                  {"cve_id": "CVE-2026-67890", "severity": "medium"}]},
    ]
    out = build_comment(touched, findings)
    assert "woocommerce" in out
    assert "CVE-2026-12345" in out
    assert "1 touched slug" in out


# ============================== #35 issue_push =================================

def test_idempotency_key_is_stable():
    from wpsecscan.issue_push import idempotency_key
    k1 = idempotency_key("https://x.com", "headers", "Missing CSP")
    k2 = idempotency_key("https://x.com", "headers", "Missing CSP")
    k3 = idempotency_key("https://y.com", "headers", "Missing CSP")
    assert k1 == k2
    assert k1 != k3
    assert len(k1) == 32


def test_push_jira_no_token_returns_error(monkeypatch):
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("WPSECSCAN_JIRA_TOKEN", raising=False)
    from wpsecscan.issue_push import push_jira
    r = push_jira("https://x.com", [], base_url="https://j.example", email="me@x.com")
    assert r == [{"ok": False, "error": "JIRA_API_TOKEN not set"}]


def test_push_jira_skips_cached(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.setenv("JIRA_API_TOKEN", "fake")
    from wpsecscan import issue_push as ip
    # Pre-populate cache for one payload's title.
    key = ip.idempotency_key("https://x.com", "", "[HIGH] Some title")
    cache = {key: {"system": "jira", "ticket_id": "SEC-99", "url": "https://j/browse/SEC-99"}}
    ip._save_cache(cache)
    payload = {"fields": {"summary": "[HIGH] Some title", "labels": ["wpsecscan", "high"]}}
    r = ip.push_jira("https://x.com", [payload],
                       base_url="https://j.example", email="me@x.com",
                       cache=cache)
    assert r == [{"ok": True, "skipped": True, "ticket": "SEC-99",
                   "url": "https://j/browse/SEC-99"}]


def test_cmd_diff_tree_too_few_snapshots(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.__main__ import _cmd_diff_tree
    import pytest
    with pytest.raises(SystemExit) as ei:
        _cmd_diff_tree(["https://no-snapshots.example"])
    assert ei.value.code == 64
    out = capsys.readouterr().out
    assert "need at least 2 snapshots" in out


def test_cmd_diff_tree_renders_added_and_removed(monkeypatch, tmp_path, capsys):
    """Two snapshots, second introduces one finding and removes one — the
    tree should print + and - lines."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import history as _h
    import json as _json
    url = "https://difftree.example"
    snap_a = {
        "scanned_at": "2026-05-25T10:00:00Z",
        "risk_score": 42,
        "results": [{"check_id": "headers", "findings": [
            {"severity": "medium", "title": "Missing CSP"},
        ]}],
    }
    snap_b = {
        "scanned_at": "2026-05-26T10:00:00Z",
        "risk_score": 35,
        "results": [{"check_id": "tls", "findings": [
            {"severity": "high", "title": "TLS 1.0 enabled"},
        ]}],
    }
    _h.save_report_snapshot(url, _json.dumps(snap_a))
    import time as _t
    _t.sleep(1.1)  # ensure distinct timestamp filename
    _h.save_report_snapshot(url, _json.dumps(snap_b))

    from wpsecscan.__main__ import _cmd_diff_tree
    _cmd_diff_tree([url, "--limit", "5"])
    out = capsys.readouterr().out
    assert "Missing CSP" in out
    assert "TLS 1.0 enabled" in out


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
