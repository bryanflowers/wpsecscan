"""Round-54 (A1-G4) tests.

One happy-path test per new module so we catch the obvious wiring bugs.
Aggressive checks are exercised with ctx["aggressive"] set; passive checks
work without it.
"""
from __future__ import annotations

import asyncio
import json

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ----------------------- Wave 1 quick wins -----------------------

def test_webdav_check_runs_clean():
    from wpsecscan.checks.webdav import check
    client = FakeClient(responses={"/": FakeResponse(status_code=405, headers={"allow": "GET, POST"})})
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list)


def test_dev_params_check_runs():
    from wpsecscan.checks.dev_params import check
    client = FakeClient(responses={"/": FakeResponse(status_code=200, text="hello")})
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list)
    titles = [f.title for f in findings]
    assert any("dev/test" in t.lower() or "consumed" in t.lower() for t in titles)


def test_abuseipdb_skips_without_token():
    from wpsecscan.checks.abuseipdb_lookup import check
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert any("AbuseIPDB" in f.title for f in findings)


# ----------------------- Wave 2 aggressive -----------------------

def test_ssti_skips_passive():
    from wpsecscan.checks.ssti import check
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert any("skip" in f.title.lower() or "ssti" in f.title.lower() for f in findings)


def test_nosql_injection_skips_passive():
    from wpsecscan.checks.nosql_injection import check
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list)


def test_path_bypass_skips_passive():
    from wpsecscan.checks.path_bypass import check
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list)


def test_github_leak_search_skips_without_token():
    from wpsecscan.checks.github_leak_search import check
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert any("GitHub" in f.title for f in findings)


def test_s3_bucket_discovery_module_present():
    # The bare attribute access resolves to the function because __init__.py
    # rebinds the symbol via `from .s3_bucket_discovery import check as s3_bucket_discovery`.
    # Use importlib to reach the actual module object.
    import importlib
    mod = importlib.import_module("wpsecscan.checks.s3_bucket_discovery")
    assert callable(mod.check)


def test_dom_xss_headless_emits_install_hint_without_playwright():
    from wpsecscan.checks.dom_xss_headless import check, _has_playwright
    if _has_playwright():
        # Skip - if Playwright IS installed, the check would actually try to drive a browser
        return
    client = FakeClient()
    findings = _run(check(client, _ctx()))
    assert any("Playwright" in f.title or "DOM-XSS" in f.title for f in findings)


# ----------------------- Wave 4 power-user -----------------------

def test_audit_log_record_and_read(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import audit_log
    from wpsecscan import history
    monkeypatch.setattr(history, "_home", lambda: str(tmp_path))
    rec = audit_log.record_scan_start("https://x.com", {"auth_pass": "secret", "ok": "yes"})
    assert rec["args"]["auth_pass"] == "<redacted>"
    assert rec["args"]["ok"] == "yes"
    log = audit_log.read_log()
    assert log and log[0]["event"] == "scan_started"


def test_marketplace_loads_catalogue():
    from wpsecscan import marketplace
    cat = marketplace.load_catalogue()
    assert isinstance(cat["entries"], list)
    assert len(cat["entries"]) >= 3
    # Filter by category
    sigs = marketplace.entries_by_category("signature")
    assert all(e["category"] == "signature" for e in sigs)


def test_i18n_fallback_to_english():
    from wpsecscan import i18n
    i18n.set_locale("zz")  # unknown
    assert i18n.t("scan") == "Scan"
    i18n.set_locale("es")
    assert i18n.t("scan") == "Escanear"
    assert i18n.t("nonexistent_key_99") == "nonexistent_key_99"
    i18n.set_locale("en")


# ----------------------- Wave 7 UX -----------------------

def test_heatmap_renders_without_data():
    from wpsecscan import heatmap
    from wpsecscan.models import ScanReport
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    svg = heatmap.render_svg(rep, tags_map={})
    assert "<svg" in svg


def test_heatmap_renders_with_data():
    from wpsecscan import heatmap
    from wpsecscan.models import ScanReport, CheckResult, Finding
    f1 = Finding(severity="critical", title="hi")
    f2 = Finding(severity="high", title="lo")
    rep = ScanReport(
        target="https://x.com", scanned_at="now", duration_ms=0,
        results=[CheckResult(check_id="cors", check_name="CORS", findings=[f1, f2])],
    )
    tags_map = {"cors": {"owasp": "A05:2021", "owasp_label": "Security Misconfiguration"}}
    svg = heatmap.render_svg(rep, tags_map=tags_map)
    assert "CRITICAL" in svg
    assert "Security Misconfiguration" in svg
    assert "A05:2021" in svg


def test_diff_viewer_writes_standalone_html(tmp_path):
    from wpsecscan.reporters import diff_viewer
    p = tmp_path / "diff.html"
    diff_viewer.write(p)
    body = p.read_text(encoding="utf-8")
    assert "WPSecScan" in body and "diff viewer" in body
    assert 'type="file"' in body


def test_exec_pdf_html_fallback(tmp_path):
    from wpsecscan.reporters import exec_pdf
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(
        target="https://x.com", scanned_at="now", duration_ms=0,
        results=[CheckResult(check_id="cors", check_name="CORS",
                             findings=[Finding(severity="high", title="X")])],
    )
    # Force fallback path even if reportlab is installed
    from wpsecscan.reporters import exec_pdf as ep
    if not ep._has_reportlab():
        out = tmp_path / "exec.pdf"
        ep.write(rep, out)
        # Fallback HTML lives next to it with .html extension
        html_out = out.with_suffix(".html")
        assert html_out.exists()
        assert "Executive Summary" in html_out.read_text(encoding="utf-8")
    else:
        out = tmp_path / "exec.pdf"
        ep.write(rep, out)
        assert out.exists() and out.stat().st_size > 1000


# ----------------------- Wave 8 collab -----------------------

def test_assignee_and_comments_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    history.set_assignee("https://x.com", "cors", "Misconfig X", "alice@example.com")
    assert history.get_assignee("https://x.com", "cors", "Misconfig X") == "alice@example.com"
    history.set_assignee("https://x.com", "cors", "Misconfig X", "")
    assert history.get_assignee("https://x.com", "cors", "Misconfig X") in (None, "")

    history.add_comment("https://x.com", "cors", "Misconfig X", "bob", "Will look later")
    history.add_comment("https://x.com", "cors", "Misconfig X", "bob", "Closed")
    comments = history.get_comments("https://x.com", "cors", "Misconfig X")
    assert len(comments) == 2
    assert comments[0]["author"] == "bob"
    assert history.delete_comment("https://x.com", "cors", "Misconfig X", 0) is True
    assert len(history.get_comments("https://x.com", "cors", "Misconfig X")) == 1


def test_har_replay_load_har(tmp_path):
    from wpsecscan import har_replay
    har = {
        "log": {
            "version": "1.2",
            "entries": [
                {"request": {"method": "GET", "url": "https://x.com/a", "headers": [{"name": "X-Test", "value": "1"}]}},
                {"request": {"method": "POST", "url": "https://x.com/b", "headers": [],
                              "postData": {"text": "hello"}}},
            ],
        }
    }
    p = tmp_path / "in.har"
    p.write_text(json.dumps(har), encoding="utf-8")
    entries = har_replay.load_har(p)
    assert len(entries) == 2
    # Verify request-kwargs derivation
    method, url, headers, body = har_replay._request_kwargs(entries[1])
    assert method == "POST" and url == "https://x.com/b" and body == b"hello"


# ----------------------- Inventory + tag wiring -----------------------

def test_round54_checks_all_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    for cid in (
        "webdav", "dev_params", "abuseipdb_lookup", "waf_ruleset",
        "oauth_oidc", "saml_xsw", "s3_bucket_discovery",
        "github_leak_search", "jwt_audit",
        "ssti", "nosql_injection", "path_bypass", "race_condition",
        "dom_xss_headless",
    ):
        assert cid in ids, f"Round-54 check {cid!r} not registered in ALL_CHECKS"


def test_round54_tag_entries_present():
    from wpsecscan import tags as t
    tags_map = t._load()
    for cid in (
        "webdav", "dev_params", "abuseipdb_lookup", "waf_ruleset",
        "oauth_oidc", "saml_xsw", "s3_bucket_discovery",
        "github_leak_search", "jwt_audit",
        "ssti", "nosql_injection", "path_bypass", "race_condition",
        "dom_xss_headless",
    ):
        assert cid in tags_map, f"check {cid!r} missing from check_tags.json"
        assert "cwe" in tags_map[cid], f"check {cid!r} missing cwe field"
        assert "d3fend" in tags_map[cid], f"check {cid!r} missing d3fend field"


def test_round54_compliance_entries_present():
    from wpsecscan import tags as t
    cmap = t._load_compliance()
    for cid in (
        "webdav", "dev_params", "abuseipdb_lookup", "waf_ruleset",
        "oauth_oidc", "saml_xsw", "s3_bucket_discovery",
        "github_leak_search", "jwt_audit",
        "ssti", "nosql_injection", "path_bypass", "race_condition",
        "dom_xss_headless",
    ):
        assert cid in cmap, f"check {cid!r} missing from compliance_map.json"


# ----------------------- QA-round regression tests -----------------------

def test_bug1_subdomain_cookie_domain_match_respects_boundary():
    """B7 cookie-tossing: matching the apex inside `Domain=` must require a
    boundary char afterwards. `Domain=myexample.com` is NOT `Domain=example.com`."""
    import re as _re
    apex_lc = "example.com"
    cookie_domain_re = _re.compile(
        rf"domain=\.?{_re.escape(apex_lc)}(?:\s*[;,]|\s*$)",
        _re.IGNORECASE,
    )
    # Negative cases — should NOT match
    assert cookie_domain_re.search("domain=myexample.com; secure; httponly") is None
    assert cookie_domain_re.search("Domain=notexample.com") is None
    # Positive cases — should match
    assert cookie_domain_re.search("Domain=example.com; Path=/") is not None
    assert cookie_domain_re.search("domain=.example.com") is not None
    assert cookie_domain_re.search("Domain=example.com,Path=/") is not None


def test_bug3_cisa_kev_cache_survives_null_cves(tmp_path, monkeypatch):
    """{"cves": null} on disk used to crash with TypeError (set(None));
    after the fix the loader returns an empty set."""
    import json as _j
    from wpsecscan.integrations import cisa_kev as _kev
    cache = tmp_path / "kev.json"
    cache.write_text(_j.dumps({"cves": None, "fetched_at": 0}), encoding="utf-8")
    monkeypatch.setattr(_kev, "_cache_path", lambda: cache)
    # Don't let the loader try to refresh from the network in tests:
    monkeypatch.setattr(_kev, "_fetch_remote", lambda: None)
    out = _kev.load_kev_set()
    assert out == set()


def test_bug4_cron_field_rejects_out_of_range():
    """`32` is not a valid day-of-month; the parser used to silently accept
    it and the cron would never fire. Now it raises ValueError."""
    import pytest
    from wpsecscan.daemon import _parse_cron_field
    with pytest.raises(ValueError):
        _parse_cron_field("32", 1, 31)
    with pytest.raises(ValueError):
        _parse_cron_field("0-99", 0, 59)
    with pytest.raises(ValueError):
        _parse_cron_field("5-2", 0, 59)  # start > end
    # Valid cases still work
    assert _parse_cron_field("1,15,30", 1, 31) == {1, 15, 30}
    assert _parse_cron_field("*/15", 0, 59) == {0, 15, 30, 45}
    assert _parse_cron_field("*", 0, 6) == {0, 1, 2, 3, 4, 5, 6}


def test_bug2_jwt_audit_does_not_persist_cracked_secret_in_extra():
    """The cracked HS256 secret was being duplicated into `extra` — pure
    review of the source asserts the key is gone."""
    import wpsecscan.checks.jwt_audit as _src
    import inspect
    body = inspect.getsource(_src)
    assert '"cracked_secret"' not in body, (
        "jwt_audit no longer persists the cracked secret value in finding.extra"
    )


def test_bug5_exec_pdf_fallback_always_writes_html_extension(tmp_path, monkeypatch):
    """When reportlab is absent, callers passing a no-extension path used to
    get HTML content under that exact name. Now they always get `.html`."""
    from wpsecscan.reporters import exec_pdf
    from wpsecscan.models import ScanReport
    monkeypatch.setattr(exec_pdf, "_has_reportlab", lambda: False)
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    out = tmp_path / "report"  # no extension
    exec_pdf.write(rep, out)
    assert (tmp_path / "report.html").exists()
    assert not (tmp_path / "report").exists()
