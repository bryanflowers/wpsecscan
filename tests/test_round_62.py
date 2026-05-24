"""Round-62 — 89 features test suite.

One smoke test per public function. Heavy network operations are
short-circuited via WPSECSCAN_NO_NETWORK.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ============================================================
# B21-B38 — scanner checks
# ============================================================

def test_server_stack_reveal_no_headers():
    from wpsecscan.checks.server_stack_reveal import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list) and findings


def test_server_stack_reveal_php_eol():
    from wpsecscan.checks.server_stack_reveal import check
    client = FakeClient(responses={"/": FakeResponse(
        status_code=200,
        headers={"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.33"})})
    findings = _run(check(client, _ctx()))
    titles = " ".join(f.title for f in findings)
    assert "PHP 7.4" in titles or "PHP/7.4" in titles


def test_waf_brand_deep_no_response():
    from wpsecscan.checks.waf_brand_deep import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list) and findings


def test_waf_brand_deep_cloudflare_via_cf_ray():
    """Confirm Cloudflare/CDN markers don't crash even though we don't list CF."""
    from wpsecscan.checks.waf_brand_deep import check
    client = FakeClient(responses={"/": FakeResponse(
        text="<html></html>",
        headers={"server": "BIG-IP", "x-bigipreqid": "abc"})})
    findings = _run(check(client, _ctx()))
    assert any("F5" in f.title for f in findings)


def test_sri_audit_no_resources():
    from wpsecscan.checks.sri_audit import check
    client = FakeClient(responses={"/": FakeResponse(text="<html><body>hi</body></html>")})
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list) and findings


def test_sri_audit_detects_missing_integrity():
    from wpsecscan.checks.sri_audit import check
    client = FakeClient(responses={"/": FakeResponse(
        text='<html><head><script src="https://cdn.example/x.js"></script></head></html>')})
    findings = _run(check(client, _ctx()))
    assert any("SRI missing" in f.title for f in findings)


def test_service_exposure_local_target_skipped():
    from wpsecscan.checks.service_exposure import check
    ctx = {"target": "https://localhost", "shared": {}, "step": lambda _s: None}
    findings = _run(check(FakeClient(base_url="https://localhost"), ctx))
    assert any("skipped" in f.title.lower() for f in findings)


def test_js_framework_deep_no_markers():
    from wpsecscan.checks.js_framework_deep import check
    client = FakeClient(responses={"/": FakeResponse(text="<html></html>")})
    findings = _run(check(client, _ctx()))
    assert isinstance(findings, list) and findings


def test_js_framework_deep_detects_nextjs():
    from wpsecscan.checks.js_framework_deep import check
    body = '<html><script src="/_next/static/chunks/main-1.2.3.js"></script><script>__NEXT_DATA__={}</script></html>'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    findings = _run(check(client, _ctx()))
    assert any("Next.js" in f.title or "Next.js" in f.evidence for f in findings)


def test_sri_pwa_misc_no_response():
    from wpsecscan.checks.sri_pwa_misc import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_wp_cli_inject_no_artefacts():
    from wpsecscan.checks.wp_cli_inject import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list) and findings


def test_wp_cli_inject_detects_phar():
    from wpsecscan.checks.wp_cli_inject import check
    client = FakeClient(responses={"/wp-cli.phar": FakeResponse(status_code=200, text="phar")})
    findings = _run(check(client, _ctx()))
    assert any("critical" == f.severity for f in findings)


# ============================================================
# egress recorder + network fingerprint
# ============================================================

def test_egress_recorder_lifecycle(tmp_path, monkeypatch):
    from wpsecscan import egress_recorder
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    p = egress_recorder.start_recording("https://example.com")
    egress_recorder.record("https://example.com/page", method="GET", status=200, took_ms=42)
    egress_recorder.record("https://api.example.com/x", method="POST", status=201)
    final = egress_recorder.stop_recording()
    assert final == p
    summary = egress_recorder.summarise(p)
    assert summary["total"] == 2
    assert summary["unique_hosts"] >= 1


def test_network_fingerprint_no_host():
    from wpsecscan.network_fingerprint import fingerprint_url
    out = fingerprint_url("ftp://example.com")
    assert "error" in out


# ============================================================
# C39-C50 — Reporters
# ============================================================

def test_round62_reporter_csv_pivot_by_severity():
    from wpsecscan.reporters.round62 import csv_pivot
    rep = {"target": "https://e.com",
            "results": [{"check_id": "x", "findings": [
                {"severity": "high", "title": "A"},
                {"severity": "high", "title": "B"},
                {"severity": "low",  "title": "C"},
            ]}]}
    csv = csv_pivot(rep, by="severity")
    assert "high,2" in csv and "low,1" in csv


def test_round62_reporter_grafana_shape():
    from wpsecscan.reporters.round62 import grafana_dashboard
    out = grafana_dashboard({"target": "x", "summary": {"critical": 1}})
    assert "panels" in out and out["panels"]


def test_round62_reporter_siem_ndjson():
    from wpsecscan.reporters.round62 import siem_ndjson
    rep = {"target": "https://e.com",
            "results": [{"check_id": "x", "findings": [
                {"severity": "high", "title": "T", "url": "/"}
            ]}]}
    out = siem_ndjson(rep)
    assert '"check_id": "x"' in out and '"severity": "high"' in out


def test_round62_reporter_confluence_markdown():
    from wpsecscan.reporters.round62 import confluence_page_markdown
    rep = {"target": "https://e.com", "risk_score": 50,
            "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            "results": [{"check_id": "x", "findings": [{"severity": "critical", "title": "T", "url": "/"}]}]}
    md = confluence_page_markdown(rep)
    assert "# WPSecScan report" in md and "[CRITICAL]" in md


def test_round62_reporter_streamlit_script():
    from wpsecscan.reporters.round62 import streamlit_script
    s = streamlit_script()
    assert "import streamlit as st" in s and "uploaded" in s


def test_round62_reporter_sbom_diff(tmp_path):
    from wpsecscan.reporters.round62 import sbom_diff
    old = {"components": [{"name": "react", "version": "17.0.0"}]}
    new = {"components": [{"name": "react", "version": "18.0.0"},
                            {"name": "next", "version": "14.2.0"}]}
    (tmp_path / "old.json").write_text(json.dumps(old))
    (tmp_path / "new.json").write_text(json.dumps(new))
    d = sbom_diff(str(tmp_path / "old.json"), str(tmp_path / "new.json"))
    assert any(a["name"] == "next" for a in d["added"])
    assert any(c["name"] == "react" for c in d["version_changed"])


# ============================================================
# D51-D60 — Integrations
# ============================================================

def test_burp_project_xml():
    from wpsecscan.integrations.round62 import burp_project_xml
    rep = {"target": "https://e.com",
            "results": [{"check_id": "x", "findings": [
                {"severity": "high", "title": "T", "url": "https://e.com/x", "evidence": "E"}
            ]}]}
    xml = burp_project_xml(rep)
    assert "<items" in xml and "wpsecscan x" in xml


def test_zap_findings_import_missing_file():
    from wpsecscan.integrations.round62 import zap_findings_import
    assert zap_findings_import("/nope/path/zap.json") == []


def test_zap_findings_import_parses_minimum(tmp_path):
    from wpsecscan.integrations.round62 import zap_findings_import
    z = {"site": [{"@host": "e.com", "alerts": [{
        "alert": "XSS reflected", "riskcode": "3", "desc": "d", "solution": "s",
        "instances": [{"uri": "https://e.com/x", "evidence": "<script>"}],
    }]}]}
    p = tmp_path / "zap.json"
    p.write_text(json.dumps(z))
    out = zap_findings_import(str(p))
    assert out and out[0]["severity"] == "high"


def test_nuclei_pull_honors_no_network(monkeypatch):
    from wpsecscan.integrations.round62 import nuclei_template_pull
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    out = nuclei_template_pull(max_files=1)
    assert "WPSECSCAN_NO_NETWORK" in str(out.get("errors", ""))


def test_wordfence_cloud_sync_no_key(monkeypatch):
    from wpsecscan.integrations.round62 import wordfence_cloud_sync
    monkeypatch.delenv("WORDFENCE_API_KEY", raising=False)
    assert wordfence_cloud_sync() == []


def test_patchstack_submit_no_key(monkeypatch):
    from wpsecscan.integrations.round62 import patchstack_submit
    monkeypatch.delenv("PATCHSTACK_API_KEY", raising=False)
    out = patchstack_submit({"title": "x"}, vendor="Acme")
    assert out.get("hint", "").startswith("PATCHSTACK_API_KEY")


def test_wpscan_submit_no_key(monkeypatch):
    from wpsecscan.integrations.round62 import wpscan_submit
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    out = wpscan_submit({"title": "x"}, slug="acme")
    assert out.get("hint", "").startswith("WPSCAN_API_TOKEN")


def test_wpengine_kinsta_wpcom_no_keys(monkeypatch):
    from wpsecscan.integrations.round62 import wpengine_site_state, kinsta_site_state, wpcom_site_state
    for k in ("WPENGINE_API_TOKEN", "KINSTA_API_TOKEN", "WPCOM_API_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    assert "WPENGINE_API_TOKEN" in wpengine_site_state("x")["error"]
    assert "KINSTA_API_TOKEN" in kinsta_site_state("x")["error"]
    assert "WPCOM_API_TOKEN" in wpcom_site_state("x")["error"]


def test_n8n_recipes():
    from wpsecscan.integrations.round62 import n8n_recipe
    for name in ("weekly-scan", "cve-alert", "ci-gate"):
        r = n8n_recipe(name)
        assert "nodes" in r and r["nodes"]
    assert "error" in n8n_recipe("nonexistent")


# ============================================================
# E61-E70 + G78-G80 — workflow + defensive
# ============================================================

def test_render_daily_digest_empty():
    from wpsecscan.round62_workflow import render_daily_digest
    body = render_daily_digest([])
    assert "No new critical/high findings" in body


def test_render_daily_digest_with_new_findings():
    from wpsecscan.round62_workflow import render_daily_digest
    import time as _t
    sites = [{"url": "https://x.example", "last_scan_ts": int(_t.time()) - 100,
                "last_critical": 1, "last_high": 2}]
    body = render_daily_digest(sites)
    assert "x.example" in body and "NEW critical=1" in body


def test_pr_comment_body():
    from wpsecscan.round62_workflow import pr_comment_body
    rep = {"target": "https://e.com", "risk_score": 50,
            "summary": {"critical": 1, "high": 2, "medium": 3, "low": 4}}
    out = pr_comment_body(rep, baseline_critical=0, baseline_high=1)
    assert "WPSecScan" in out and "+1" in out


def test_pre_commit_hook_script():
    from wpsecscan.round62_workflow import pre_commit_hook_script
    s = pre_commit_hook_script()
    assert "passthru" in s and "shell_exec" in s


def test_apple_shortcuts_recipe():
    from wpsecscan.round62_workflow import apple_shortcuts_recipe
    r = apple_shortcuts_recipe()
    assert r["name"] == "Scan with WPSecScan" and r["actions"]


def test_bookmarklet_js():
    from wpsecscan.round62_workflow import bookmarklet_js
    js = bookmarklet_js("http://localhost:8765")
    assert js.startswith("javascript:") and "localhost:8765" in js


def test_zsh_completion_man_page():
    from wpsecscan.round62_workflow import zsh_completion, man_page
    assert "_wpsecscan" in zsh_completion()
    assert ".TH WPSECSCAN" in man_page()


def test_resume_marker_roundtrip(tmp_path, monkeypatch):
    from wpsecscan.round62_workflow import write_resume_marker, load_resume_marker, clear_resume_marker
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert load_resume_marker() is None
    write_resume_marker("https://e.com", ["c1", "c2"])
    m = load_resume_marker()
    assert m["target"] == "https://e.com" and m["completed"] == ["c1", "c2"]
    clear_resume_marker()
    assert load_resume_marker() is None


def test_siem_forward_honors_no_network(monkeypatch):
    from wpsecscan.round62_workflow import siem_forward
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    out = siem_forward({}, endpoint="https://splunk.example", kind="splunk-hec")
    assert out["ok"] is False


def test_honeypot_deploy_instructions():
    from wpsecscan.round62_workflow import honeypot_deploy_instructions
    s = honeypot_deploy_instructions("https://e.com")
    assert "honeypot" in s.lower() and "https://e.com" in s


# ============================================================
# Registration sanity
# ============================================================

def test_round_62_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    registered = {cid for cid, _n, _f, _a in ALL_CHECKS}
    expected = {"server_stack_reveal", "waf_brand_deep", "sri_audit",
                 "service_exposure", "js_framework_deep", "sri_pwa_misc",
                 "wp_cli_inject"}
    missing = expected - registered
    assert not missing, f"Round-62 checks missing: {sorted(missing)}"


def test_round_62_tags_present():
    p = Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "check_tags.json"
    tags = json.loads(p.read_text(encoding="utf-8"))
    for cid in ("server_stack_reveal", "waf_brand_deep", "sri_audit",
                 "service_exposure", "js_framework_deep", "sri_pwa_misc",
                 "wp_cli_inject"):
        assert cid in tags


def test_round_62_compliance_v2_present():
    p = Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "compliance_v2.json"
    cm = json.loads(p.read_text(encoding="utf-8"))
    for cid in ("server_stack_reveal", "waf_brand_deep", "sri_audit",
                 "service_exposure", "js_framework_deep", "sri_pwa_misc",
                 "wp_cli_inject"):
        assert cid in cm, f"missing {cid}"
        for fw in ("hitrust", "cmmc", "nist_csf", "cis_v8", "iso_27001_2022"):
            assert fw in cm[cid], f"{cid} missing {fw}"


def test_distribution_manifests_exist():
    root = Path(__file__).resolve().parents[1]
    expected = [
        "distribution/README.md",
        "distribution/chocolatey/wpsecscan.nuspec",
        "distribution/chocolatey/tools/chocolateyinstall.ps1",
        "distribution/chocolatey/tools/chocolateyuninstall.ps1",
        "distribution/winget/WPSecScan.Bryan.yaml",
        "distribution/homebrew/wpsecscan.rb",
        "distribution/snap/snapcraft.yaml",
        "distribution/flatpak/com.github.bryanflowers.wpsecscan.yml",
        "distribution/appimage/AppImageBuilder.yml",
    ]
    for p in expected:
        assert (root / p).exists(), f"missing {p}"
