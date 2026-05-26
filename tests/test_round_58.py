"""Round-58 — 117-feature smoke tests."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ---- Wave P: WP deep dives ----

def test_gutenberg_blocks_clean():
    from wpsecscan.checks.gutenberg_blocks import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("Gutenberg" in f.title for f in findings)


def test_wp_cron_dos_unreachable():
    from wpsecscan.checks.wp_cron_dos import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("wp-cron" in f.title.lower() for f in findings)


def test_rest_permission_audit_no_root():
    from wpsecscan.checks.rest_permission_audit import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("REST" in f.title for f in findings)


def test_wp_query_sqli_passive():
    from wpsecscan.checks.wp_query_sqli import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() or "passive" in f.title.lower() for f in findings)


def test_wp_salts_age_no_nonces():
    from wpsecscan.checks.wp_salts_age import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_heartbeat_abuse_unreachable():
    from wpsecscan.checks.heartbeat_abuse import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("heartbeat" in f.title.lower() for f in findings)


def test_woocommerce_deep_clean():
    from wpsecscan.checks.woocommerce_deep import check
    findings = _run(check(FakeClient(responses={"/": FakeResponse(text="<html>clean</html>")}), _ctx()))
    assert isinstance(findings, list)


# ---- Wave Q: cloud ----

def test_hosting_platform_audit_clean():
    from wpsecscan.checks.hosting_platform_audit import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_origin_ip_discovery_unhostable():
    from wpsecscan.checks.origin_ip_discovery import check
    findings = _run(check(FakeClient(), {"target": "https://localhost-doesnt-exist.invalid",
                                          "shared": {}, "step": lambda _s: None}))
    assert isinstance(findings, list)


# ---- Wave R: exploit primitives ----

def test_http2_smuggling_passive():
    from wpsecscan.checks.http2_smuggling import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_upload_bypass_passive():
    from wpsecscan.checks.upload_bypass_deep import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_misc_injection_passive():
    from wpsecscan.checks.misc_injection_audit import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_tls_reneg_dos_http_target():
    from wpsecscan.checks.tls_reneg_dos import check
    findings = _run(check(FakeClient(),
                          {"target": "http://example.com", "shared": {}, "step": lambda _s: None}))
    assert any("non-HTTPS" in f.title or "TLS" in f.title for f in findings)


def test_cache_poisoning_v2_passive():
    from wpsecscan.checks.cache_poisoning_v2 import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


# ---- Wave S: OSINT ----

def test_osint_module_imports():
    from wpsecscan.integrations import osint
    assert callable(osint.asn_for_ip)
    assert callable(osint.geo_for_ip)


# ---- Wave T: compliance + bounty ----


def test_bounty_format_h1():
    from wpsecscan.reporters.bounty_format import format_for_hackerone
    from wpsecscan.models import Finding
    out = format_for_hackerone(Finding(severity="high", title="Test", evidence="e", remediation="r"))
    assert "Test" in out and "**Severity**" in out


def test_trust_center_html():
    from wpsecscan.reporters.bounty_format import trust_center_html
    from wpsecscan.models import ScanReport
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    html = trust_center_html(rep, brand="Acme")
    assert "<title>Acme" in html


# ---- Wave U: continuous ----


# ---- Wave V: exec pack ----

def test_executive_pack_costs():
    from wpsecscan.reporters.executive_pack import cost_estimates, priority_queue
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0,
                     results=[CheckResult(check_id="sqli", check_name="SQLi",
                                          findings=[Finding(severity="high", title="X")])])
    c = cost_estimates(rep)
    assert c["total_breach_exposure"] > 0
    q = priority_queue(rep)
    assert len(q) >= 1


# ---- Wave W: AI ----

def test_ai_assist_no_key(monkeypatch):
    from wpsecscan import ai_assist
    for var in ("WPSECSCAN_OPENAI_API_KEY", "OPENAI_API_KEY",
                "WPSECSCAN_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY",
                "WPSECSCAN_OLLAMA_URL"):
        monkeypatch.delenv(var, raising=False)
    assert ai_assist.is_configured() is False
    assert ai_assist.llm("hi") == ""


# ---- Wave Y: perf ----

def test_bloom_filter():
    from wpsecscan.perf import BloomFilter
    b = BloomFilter(capacity=1000)
    b.add("hello")
    assert "hello" in b
    assert "world" not in b


# ---- Wave Z: UX polish ----


# ---- Wave AA: observability ----

def test_self_health():
    from wpsecscan.observability import self_health
    h = self_health()
    assert "memory_kb" in h


def test_perf_trend_empty():
    from wpsecscan.observability import perf_trend
    assert perf_trend("nonexistent_check") == []


# ---- Wave BB: scanner security ----


# ---- Wave CC: education ----

def test_tutorial_steps_loaded():
    from wpsecscan.education import tutorial_steps
    assert len(tutorial_steps()) >= 5


def test_plain_english_known():
    from wpsecscan.education import plain_english
    assert plain_english("sqli") != ""
    assert plain_english("nonexistent_check_xyz") == ""


# ---- Inventory ----

def test_round58_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    for cid in ("gutenberg_blocks", "wp_cron_dos", "rest_permission_audit",
                "wp_query_sqli", "wp_salts_age", "heartbeat_abuse",
                "woocommerce_deep", "hosting_platform_audit",
                "origin_ip_discovery", "tls_reneg_dos", "osint_enrich",
                "http2_smuggling", "upload_bypass_deep",
                "misc_injection_audit", "cache_poisoning_v2",
                "plugin_specific_audit"):
        assert cid in ids


def test_round58_tags_present():
    from wpsecscan import tags
    tmap = tags._load()
    for cid in ("gutenberg_blocks", "wp_cron_dos", "rest_permission_audit",
                "wp_salts_age", "osint_enrich"):
        assert cid in tmap
        assert "cwe" in tmap[cid] and "d3fend" in tmap[cid]
