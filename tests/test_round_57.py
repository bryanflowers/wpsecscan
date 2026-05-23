"""Round-57 — 40-feature parity tests.

One happy-path test per new module to verify wiring + basic correctness.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx(extra=None):
    base = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    if extra:
        base.update(extra)
    return base


# ---------- Wave A: wpscan parity ----------

def test_timthumb_no_paths():
    from wpsecscan.checks.timthumb import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("timthumb" in f.title.lower() for f in findings)


def test_plugin_hash_no_plugins():
    from wpsecscan.checks.plugin_hash_fingerprint import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_ua_rotation_returns_string():
    from wpsecscan import ua_rotation
    ua = ua_rotation.random_ua()
    assert isinstance(ua, str) and "Mozilla" in ua
    assert ua_rotation.pool_size() >= 15


def test_rate_limit_parses_headers():
    from wpsecscan import rate_limit
    rate_limit.update_from_headers("test-svc", {
        "x-ratelimit-remaining": "5",
        "x-ratelimit-limit": "100",
    })
    assert rate_limit.snapshot()["test-svc"]["remaining"] == 5


def test_users_deep_no_response():
    from wpsecscan.checks.users_deep import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("user" in f.title.lower() or "enum" in f.title.lower() for f in findings)


def test_plugin_archive_fuzz_skips_no_plugins():
    from wpsecscan.checks.plugin_archive_fuzz import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("no plugins" in f.title.lower() for f in findings)


def test_premium_license_clean():
    from wpsecscan.checks.premium_license_leak import check
    client = FakeClient(responses={"/": FakeResponse(text="<html>nothing here</html>")})
    findings = _run(check(client, _ctx()))
    assert any("clean" in f.title.lower() or "premium" in f.title.lower() for f in findings)


def test_xmlrpc_method_brute_skips_no_endpoint():
    from wpsecscan.checks.xmlrpc_method_brute import check
    client = FakeClient(responses={"/xmlrpc.php": FakeResponse(status_code=404)})
    findings = _run(check(client, _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


# ---------- Wave B: nuclei ----------

def test_yaml_templates_skipped_without_yaml():
    from wpsecscan.checks.yaml_templates import check
    findings = _run(check(FakeClient(), _ctx()))
    # Either "PyYAML not installed" or "no templates found"
    titles = [f.title.lower() for f in findings]
    assert any("template" in t for t in titles)


def test_workflow_module_imports():
    from wpsecscan import workflow
    assert callable(workflow.run_all_workflows)


def test_template_engine_matchers():
    from wpsecscan.template_engine import _MATCHERS, _select_part
    assert "status" in _MATCHERS
    assert "word" in _MATCHERS
    assert "regex" in _MATCHERS


def test_interactsh_id_format():
    from wpsecscan import interactsh
    s = interactsh.InteractshSession()
    assert len(s.correlation_id) == 20
    assert s.host.endswith(".oast.live") or "oast" in s.host


def test_auto_scan_detect_tech():
    from wpsecscan import auto_scan
    techs = auto_scan.detect_tech({"shared": {"core_version": "6.5"}})
    assert "wordpress" in techs


def test_template_signature_no_manifest():
    from wpsecscan.template_signature import filter_verified
    from pathlib import Path
    verified, tampered = filter_verified(Path("/nonexistent"), [Path("a"), Path("b")])
    assert len(verified) == 2 and tampered == []


# ---------- Wave C: ZAP ----------

def test_scan_modes_apply():
    from wpsecscan.scan_modes import apply_mode
    class A: pass
    a = A(); a.concurrency = 10
    apply_mode(a, "active")
    assert a.aggressive is True
    assert a.concurrency == 5  # halved


def test_session_context_list_empty(tmp_path, monkeypatch):
    from wpsecscan import session_context, history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    assert session_context.list_contexts() == []


def test_forced_browse_loads_wordlist():
    from wpsecscan.checks.forced_browse import _load_wordlist
    paths = _load_wordlist()
    assert len(paths) > 50
    assert ".env" in paths


def test_marketplace_load_static_only():
    from wpsecscan import marketplace
    # include_remote=False should never touch the network
    cat = marketplace.load_catalogue(include_remote=False)
    assert isinstance(cat["entries"], list)


def test_websocket_fuzz_skips_passive():
    from wpsecscan.checks.websocket_fuzz import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() or "passive" in f.title.lower() for f in findings)


def test_openapi_scanner_no_spec():
    from wpsecscan.checks.openapi_scanner import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("openapi" in f.title.lower() for f in findings)


def test_alert_filters_load_empty(tmp_path, monkeypatch):
    from wpsecscan import alert_filters, history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    assert alert_filters.load_filters() == []


def test_js_plugin_list_empty(tmp_path, monkeypatch):
    from wpsecscan import js_plugin, history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    assert js_plugin.list_js_plugins() == []


# ---------- Wave D: turbo-intruder ----------

def test_turbo_engine_build_raw_request():
    from wpsecscan.turbo_engine import _build_raw_request
    head, final = _build_raw_request("POST", "x.com", "/api",
                                       {"Content-Type": "application/json"}, b'{"a":1}')
    assert b"POST /api HTTP/1.1" in head
    assert b"Host: x.com" in head
    assert final.startswith(b"\r\n") and final.endswith(b'{"a":1}')


def test_response_diff_no_outliers():
    from wpsecscan.response_diff import diff
    out = diff([{"status": 200, "len": 1000, "body_hash": "abc"}] * 5)
    assert out["outliers"] == []


def test_response_diff_finds_outlier():
    from wpsecscan.response_diff import diff
    rs = [{"status": 200, "len": 1000, "body_hash": "abc"}] * 4 + \
         [{"status": 500, "len": 5000, "body_hash": "xyz"}]
    out = diff(rs)
    assert 4 in out["outliers"]


def test_attack_scripts_scaffold_template_includes_run_fn():
    from wpsecscan.attack_scripts import SCAFFOLD
    assert "def run(target, engine, Finding):" in SCAFFOLD


def test_attack_checkpoint_persistence(tmp_path, monkeypatch):
    from wpsecscan import attack_checkpoint, history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    attack_checkpoint.save_state("foo", {"completed_indices": [1, 2, 3]})
    loaded = attack_checkpoint.load_state("foo")
    assert loaded["completed_indices"] == [1, 2, 3]
    assert attack_checkpoint.clear_state("foo") is True


# ---------- Wave E: cross-cutting ----------

def test_burp_import_missing_file():
    from wpsecscan.burp_import import import_burp_project
    import pytest
    with pytest.raises(FileNotFoundError):
        import_burp_project(Path("/nonexistent/foo.burp"))


def test_pcap_replay_no_scapy_returns_note():
    from wpsecscan.pcap_replay import import_pcap, _has_scapy
    if _has_scapy():
        return
    har = import_pcap(Path("/nonexistent.pcap"))
    assert har["log"]["entries"] == []
    assert "_note" in har["log"]


def test_mobile_app_endpoints_skips_when_absent():
    from wpsecscan.checks.mobile_app_endpoints import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("mobile" in f.title.lower() or "association" in f.title.lower() for f in findings)


def test_intel_freshness_report():
    from wpsecscan import intel_freshness
    rep = intel_freshness.report()
    assert isinstance(rep, list)
    for entry in rep:
        assert "source" in entry and "status" in entry


def test_host_recon_skips_no_hostname():
    from wpsecscan.checks.host_recon import check
    findings = _run(check(FakeClient(), {"target": "not-a-url",
                                          "shared": {}, "step": lambda _s: None}))
    # localhost falls through to actual probe, so just verify the call returns
    assert isinstance(findings, list)


# ---------- Inventory ----------

def test_round57_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    for cid in (
        "timthumb", "plugin_hash_fingerprint", "users_deep", "plugin_archive_fuzz",
        "premium_license_leak", "xmlrpc_method_brute", "yaml_templates",
        "yaml_workflows", "dns_templates", "headless_templates", "spider_crawl",
        "forced_browse", "websocket_fuzz", "openapi_scanner",
        "mobile_app_endpoints", "host_recon",
    ):
        assert cid in ids, f"round-57 check {cid!r} not registered"


def test_round57_tags_present():
    from wpsecscan import tags
    tmap = tags._load()
    for cid in (
        "timthumb", "plugin_hash_fingerprint", "users_deep", "plugin_archive_fuzz",
        "premium_license_leak", "xmlrpc_method_brute", "yaml_templates",
        "yaml_workflows", "dns_templates", "headless_templates", "spider_crawl",
        "forced_browse", "websocket_fuzz", "openapi_scanner",
        "mobile_app_endpoints", "host_recon",
    ):
        assert cid in tmap and "cwe" in tmap[cid] and "d3fend" in tmap[cid]
