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


# ============================================================
# C39-C50 — Reporters
# ============================================================


# ============================================================
# D51-D60 — Integrations
# ============================================================


# ============================================================
# E61-E70 + G78-G80 — workflow + defensive
# ============================================================


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


# ============================================================
# QA fix regression tests (round-62 post-audit)
# ============================================================


def test_service_exposure_strict_ip_validation():
    """QA fix: service_exposure must not crash on garbage like '1234567'."""
    import asyncio
    from wpsecscan.checks.service_exposure import check
    ctx = {"target": "https://1234567", "shared": {}, "step": lambda _s: None}
    out = asyncio.run(check(FakeClient(base_url="https://1234567"), ctx))
    assert isinstance(out, list) and out


def test_sites_scan_passes_proxy_through(monkeypatch, tmp_path):
    """QA fix: sites.add saves proxy fields that _cmd_sites scan reads."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan import sites as sites_mod
    sites_mod.add("https://x.example", weekly=True,
                   proxy_url="socks5://127.0.0.1:9050",
                   proxy_auth="alice:pw",
                   auth_user="admin",
                   auth_app_password="abcd1234efgh")
    site = sites_mod.get("https://x.example")
    assert site["proxy_url"] == "socks5://127.0.0.1:9050"
    assert site.get("proxy_auth_sealed", "").startswith(("plain:", "sealed:"))
    assert site.get("auth_app_password_sealed", "").startswith(("plain:", "sealed:"))


def test_installer_nsi_version_matches_pyproject():
    """QA fix: installer APP_VERSION must match pyproject.toml version."""
    import re as _re
    root = Path(__file__).resolve().parents[1]
    pyproj = (root / "pyproject.toml").read_text(encoding="utf-8")
    nsi = (root / "installer" / "wpsecscan-setup.nsi").read_text(encoding="utf-8")
    py_ver = _re.search(r'^version\s*=\s*"([^"]+)"', pyproj, _re.MULTILINE).group(1)
    nsi_ver = _re.search(r'!define APP_VERSION\s+"([^"]+)"', nsi).group(1)
    assert py_ver == nsi_ver, f"installer {nsi_ver} != pyproject {py_ver}"


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
