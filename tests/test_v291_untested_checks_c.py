"""v2.9.1 W11 (lane C) - offline tests for registered checks that had zero
references anywhere in ``tests/`` (last third of the sorted untested set).

Every check is driven as ``fn(client, ctx)`` against a scripted in-memory
client (``tests.conftest.FakeClient``); nothing here touches the network.
``wpsecscan.http.Client`` / ``httpx.Client`` / ``httpx.AsyncClient`` are
replaced with tripwires so an accidental real client fails loudly, and HOME
is sandboxed so no ``~/.wpsecscan`` state is written.

Per check: a no-raise/returns-list smoke over several degenerate clients,
plus (where the logic is simple) one triggering and one non-triggering case
asserting severity / title / evidence.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from tests.conftest import FakeClient, FakeResponse

# The slice of the sorted untested-check list this file owns ([2n//3:]).
LANE_C_IDS = (
    "service_worker_scope_hijack",
    "solidity_abi_leak",
    "speculation_rules_audit",
    "stripe_webhook_audit",
    "tailwind_css_comment_leak",
    "theme_json_font_ssrf",
    "translation_plugin_key_leak",
    "trellis_yaml_audit",
    "turnstile_sitekey_reuse",
    "uploads_year_listing",
    "users_me_capability_leak",
    "vendor_backdoor_patterns",
    "vercel_preview_url_leak",
    "wc_api_key_escalation",
    "wc_coupon_enum",
    "wc_hpos_namespace_drift",
    "wc_stores_api_rate_limit_oracle",
    "web3_wallet_connector_audit",
    "webhook_signing_secrets",
    "woo_blocks_checkout_drift",
    "woo_subscriptions_renewal_race",
    "woocommerce_order_idor",
    "wp_cli_http_exposure",
    "wp_cron_cpu",
    "wp_debug_display_via_rest",
    "wp_mail_smtp_site_health_leak",
    "wp_playground_sqlite",
    "wpconfig_hardening_audit",
    "wpcron_suspicious_jobs",
    "xmlrpc_amplification",
    "yarn_pnpm_lock_audit",
)


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _offline_sandbox(monkeypatch, tmp_path):
    """Sandbox HOME, disable live feeds, and trip on any real HTTP client."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")

    import httpx

    import wpsecscan.http

    class _NoNetwork:
        def __init__(self, *args, **kwargs) -> None:
            raise AssertionError("real HTTP client constructed in an offline test")

    monkeypatch.setattr(wpsecscan.http, "Client", _NoNetwork)
    monkeypatch.setattr(httpx, "AsyncClient", _NoNetwork)
    monkeypatch.setattr(httpx, "Client", _NoNetwork)


def _ctx() -> dict:
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


def _registry() -> dict:
    from wpsecscan.checks import ALL_CHECKS

    return {cid: (fn, aggressive) for cid, _name, fn, aggressive in ALL_CHECKS}


def _fn(cid: str):
    return _registry()[cid][0]


def _run(cid: str, client: FakeClient) -> list:
    return asyncio.run(_fn(cid)(client, _ctx()))


def _client(responses: dict | None = None) -> FakeClient:
    return FakeClient(base_url="https://example.com", responses=responses or {})


def _sevs(findings: list) -> list[str]:
    return [f.severity for f in findings]


# ---------------------------------------------------------------------------
# registry + smoke over degenerate clients
# ---------------------------------------------------------------------------
def test_lane_c_ids_registered_and_passive():
    reg = _registry()
    for cid in LANE_C_IDS:
        assert cid in reg, f"{cid} missing from ALL_CHECKS"
        assert reg[cid][1] is False, f"{cid} unexpectedly aggressive"


_DEGENERATE = {
    "no-response": lambda: _client({}),
    "all-404": lambda: _client({"*": FakeResponse(status_code=404)}),
    "all-500": lambda: _client({"*": FakeResponse(status_code=500, text="error")}),
    "all-200-empty": lambda: _client({"*": FakeResponse(status_code=200)}),
    "all-200-html": lambda: _client({"*": FakeResponse(status_code=200, text="<html><body>hi</body></html>")}),
}


@pytest.mark.parametrize("variant", sorted(_DEGENERATE))
@pytest.mark.parametrize("cid", LANE_C_IDS)
def test_returns_list_and_does_not_raise(cid, variant):
    findings = _run(cid, _DEGENERATE[variant]())
    assert isinstance(findings, list)
    for f in findings:
        assert f.severity in {"info", "low", "medium", "high", "critical"}
        assert f.title


# ---------------------------------------------------------------------------
# service_worker_scope_hijack
# ---------------------------------------------------------------------------
_SW = "/wp-content/plugins/pwa-for-wp/sw.js"


def test_service_worker_allowed_header_triggers():
    c = _client({_SW: FakeResponse(200, "self.addEventListener('fetch',()=>{});",
                                   headers={"service-worker-allowed": "/"})})
    out = _run("service_worker_scope_hijack", c)
    assert _sevs(out) == ["medium"]
    assert out[0].extra["path"] == _SW


def test_service_worker_body_scope_triggers():
    c = _client({_SW: FakeResponse(200, "navigator.serviceWorker.register(u,{scope:'/'})")})
    assert _sevs(_run("service_worker_scope_hijack", c)) == ["medium"]


def test_service_worker_plain_body_is_clean():
    c = _client({_SW: FakeResponse(200, "var a=1;")})
    assert _run("service_worker_scope_hijack", c) == []


# ---------------------------------------------------------------------------
# solidity_abi_leak
# ---------------------------------------------------------------------------
def test_solidity_abi_with_admin_method_is_medium():
    abi = json.dumps([{"type": "function", "name": "withdrawAll"}])
    out = _run("solidity_abi_leak", _client({"/contracts/abi.json": FakeResponse(200, abi)}))
    assert _sevs(out) == ["medium"]
    assert out[0].extra["admin_methods"] == ["withdrawAll"]


def test_solidity_abi_benign_is_low():
    abi = json.dumps({"abi": [{"type": "function", "name": "balanceOf"}]})
    out = _run("solidity_abi_leak", _client({"/wp-content/abi.json": FakeResponse(200, abi)}))
    assert _sevs(out) == ["low"]
    assert out[0].extra["admin_methods"] == []


def test_solidity_abi_directory_listing_is_low():
    body = "<html><title>Index of /abi/</title>Parent Directory</html>"
    out = _run("solidity_abi_leak", _client({"/abi/": FakeResponse(200, body)}))
    assert _sevs(out) == ["low"]
    assert "Directory listing: yes" in out[0].evidence


def test_solidity_abi_embedded_source_is_medium():
    body = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;"
    out = _run("solidity_abi_leak", _client({"/build/contracts/": FakeResponse(200, body)}))
    assert _sevs(out) == ["medium"]
    assert "Source code embedded" in out[0].evidence


def test_solidity_abi_unrelated_json_is_clean():
    out = _run("solidity_abi_leak", _client({"/wp-content/abi.json": FakeResponse(200, '{"hello": 1}')}))
    assert out == []


# ---------------------------------------------------------------------------
# speculation_rules_audit
# ---------------------------------------------------------------------------
def _spec_page(rules: str) -> FakeResponse:
    return FakeResponse(200, f'<html><script type="speculationrules">{rules}</script></html>')


def test_speculation_rules_admin_and_immediate_trigger():
    rules = json.dumps({"prerender": [{"urls": ["/wp-admin/options.php"], "eagerness": "immediate"}]})
    out = _run("speculation_rules_audit", _client({"/": _spec_page(rules)}))
    assert _sevs(out) == ["medium"]
    assert len(out[0].extra["issues"]) == 2
    assert any("admin URL" in i for i in out[0].extra["issues"])


def test_speculation_rules_cross_origin_triggers():
    rules = json.dumps({"prefetch": [{"urls": ["https://evil.test/x"], "eagerness": "moderate"}]})
    out = _run("speculation_rules_audit", _client({"/": _spec_page(rules)}))
    assert _sevs(out) == ["medium"]
    assert "cross-origin" in out[0].extra["issues"][0]


def test_speculation_rules_benign_is_clean():
    rules = json.dumps({"prefetch": [{"urls": ["/about/"], "eagerness": "moderate"}]})
    assert _run("speculation_rules_audit", _client({"/": _spec_page(rules)})) == []


def test_speculation_rules_invalid_json_is_skipped():
    assert _run("speculation_rules_audit", _client({"/": _spec_page("{not json")})) == []


def test_speculation_rules_non_object_json_does_not_crash():
    """A speculationrules block whose JSON is a list (not an object) must be
    skipped, not crash (fixed in v2.9.1: isinstance(rules, dict) guard)."""
    out = _run("speculation_rules_audit", _client({"/": _spec_page("[]")}))
    assert out == []


# ---------------------------------------------------------------------------
# stripe_webhook_audit
# ---------------------------------------------------------------------------
def test_stripe_webhook_unsigned_accepted_is_critical():
    out = _run("stripe_webhook_audit",
               _client({"/wc-api/wc_stripe": FakeResponse(200, '{"received":true}')}))
    assert _sevs(out) == ["critical"]
    assert out[0].extra["category"] == "payment-bypass"


def test_stripe_webhook_requiring_signature_is_info():
    out = _run("stripe_webhook_audit",
               _client({"/wc-api/wc_stripe": FakeResponse(400, "Missing Signature header")}))
    assert _sevs(out) == ["info"]


def test_stripe_webhook_400_without_signature_hint_is_clean():
    out = _run("stripe_webhook_audit",
               _client({"/wc-api/wc_stripe": FakeResponse(400, "bad request")}))
    assert out == []


def test_stripe_webhook_404_405_skipped():
    c = _client({"/wc-api/wc_stripe": FakeResponse(404), "/wc-api/wc_stripe_webhooks": FakeResponse(405)})
    assert _run("stripe_webhook_audit", c) == []


# ---------------------------------------------------------------------------
# tailwind_css_comment_leak
# ---------------------------------------------------------------------------
_HOME_WITH_CSS = '<html><link rel="stylesheet" href="/wp-content/themes/x/app.css?ver=1"></html>'


def test_tailwind_css_comment_leak_triggers():
    css = "body{margin:0}\n/*# sourceMappingURL=app.css.map */\n/* built in /home/dev/project/src */"
    c = _client({"/": FakeResponse(200, _HOME_WITH_CSS),
                 "/wp-content/themes/x/app.css?ver=1": FakeResponse(200, css)})
    out = _run("tailwind_css_comment_leak", c)
    assert _sevs(out) == ["low"]
    assert "sourceMappingURL" in out[0].evidence
    assert "Linux home-path" in out[0].evidence


def test_tailwind_css_without_comments_is_clean():
    c = _client({"/": FakeResponse(200, _HOME_WITH_CSS),
                 "/wp-content/themes/x/app.css?ver=1": FakeResponse(200, "body{margin:0}")})
    assert _run("tailwind_css_comment_leak", c) == []


def test_tailwind_css_html_soft_404_and_cdn_are_skipped():
    home = '<link href="https://cdn.example.net/a.css"><link href="/b.css">'
    c = _client({"/": FakeResponse(200, home),
                 "/b.css": FakeResponse(200, "<html>/* /home/dev/x/y */</html>")})
    assert _run("tailwind_css_comment_leak", c) == []


# ---------------------------------------------------------------------------
# theme_json_font_ssrf
# ---------------------------------------------------------------------------
def _font_doc(source: str) -> str:
    return json.dumps([{"settings": {"typography": {"fontFamilies": [{"slug": "f", "source": source}]}}}])


def test_theme_json_remote_font_source_triggers():
    c = _client({"/wp-json/wp/v2/global-styles": FakeResponse(200, _font_doc("http://169.254.169.254/f.woff2"))})
    out = _run("theme_json_font_ssrf", c)
    assert _sevs(out) == ["medium"]
    assert out[0].extra["source"].startswith("http://169.254.169.254")


def test_theme_json_local_font_source_is_clean():
    c = _client({"/wp-json/wp/v2/global-styles": FakeResponse(200, _font_doc("theme"))})
    assert _run("theme_json_font_ssrf", c) == []


def test_theme_json_invalid_json_is_clean():
    c = _client({"/wp-json/wp/v2/global-styles": FakeResponse(200, "fontFamilies {not json")})
    assert _run("theme_json_font_ssrf", c) == []


# ---------------------------------------------------------------------------
# translation_plugin_key_leak
# ---------------------------------------------------------------------------
def test_translation_key_google_leak_is_high_and_stops_after_first():
    key = "AIza" + "a1B2c3D4e5" * 3 + "xyz12"  # AIza + 35 chars
    assert len(key) == 39
    c = _client({"/": FakeResponse(200, f"<script>var k='{key}';</script>"),
                 "/wp-login.php": FakeResponse(200, f"<script>var k='{key}';</script>")})
    out = _run("translation_plugin_key_leak", c)
    assert _sevs(out) == ["high"]
    assert out[0].extra["provider"] == "Google Cloud Translation API"
    assert key not in out[0].evidence  # only the 8-char prefix is echoed


def test_translation_key_azure_leak_is_high():
    body = 'headers: {"Ocp-Apim-Subscription-Key": "' + "0123456789abcdef" * 2 + '"}'
    out = _run("translation_plugin_key_leak", _client({"/wp-login.php": FakeResponse(200, body)}))
    assert _sevs(out) == ["high"]
    assert out[0].extra["provider"] == "Azure Translator"


def test_translation_key_clean_page():
    assert _run("translation_plugin_key_leak", _client({"/": FakeResponse(200, "<html>hello</html>")})) == []


# ---------------------------------------------------------------------------
# trellis_yaml_audit
# ---------------------------------------------------------------------------
def test_trellis_vault_yaml_exposed_is_critical():
    c = _client({"/group_vars/all/vault.yml": FakeResponse(200, "vault_mysql_root_password: hunter2\n")})
    out = _run("trellis_yaml_audit", c)
    assert _sevs(out) == ["critical"]
    assert out[0].extra["category"] == "trellis-exposure"


def test_trellis_non_yaml_200_is_clean():
    c = _client({"/ansible.cfg": FakeResponse(200, "<html>Welcome</html>")})
    assert _run("trellis_yaml_audit", c) == []


# ---------------------------------------------------------------------------
# turnstile_sitekey_reuse
# ---------------------------------------------------------------------------
def test_turnstile_placeholder_sitekey_is_medium():
    html = '<div class="cf-turnstile" data-sitekey="YOUR_KEY_HERE"></div>'
    out = _run("turnstile_sitekey_reuse", _client({"/": FakeResponse(200, html)}))
    assert _sevs(out) == ["medium"]
    assert out[0].extra["sitekey"] == "YOUR_KEY_HERE"


def test_turnstile_real_sitekey_is_info():
    html = '<div class="cf-turnstile" data-sitekey="0x4Bq9Z1xKpL7mN3vT8wYd"></div>'
    out = _run("turnstile_sitekey_reuse", _client({"/": FakeResponse(200, html)}))
    assert _sevs(out) == ["info"]


def test_turnstile_no_sitekey_is_clean():
    assert _run("turnstile_sitekey_reuse", _client({"/": FakeResponse(200, "<html></html>")})) == []


# ---------------------------------------------------------------------------
# uploads_year_listing
# ---------------------------------------------------------------------------
def test_uploads_year_listing_triggers_for_all_three_years():
    page = "<html><head><title>Index of /wp-content/uploads/2025</title></head></html>"
    out = _run("uploads_year_listing", _client({"*": FakeResponse(200, page)}))
    assert _sevs(out) == ["high"]
    assert len(out[0].extra["affected_paths"]) == 3
    assert "3 year(s)" in out[0].title


def test_uploads_year_listing_normal_page_is_clean():
    out = _run("uploads_year_listing", _client({"*": FakeResponse(200, "<html><h1>Welcome</h1></html>")}))
    assert out == []


# ---------------------------------------------------------------------------
# users_me_capability_leak
# ---------------------------------------------------------------------------
_ME = "/wp-json/wp/v2/users/me"


def test_users_me_401_is_info():
    out = _run("users_me_capability_leak", _client({_ME: FakeResponse(401, "{}")}))
    assert _sevs(out) == ["info"]
    assert "401" in out[0].title


def test_users_me_admin_role_is_critical():
    body = json.dumps({"name": "root", "roles": ["administrator"], "capabilities": {"manage_options": True}})
    out = _run("users_me_capability_leak", _client({_ME: FakeResponse(200, body)}))
    assert _sevs(out) == ["critical"]
    assert out[0].extra["capability_count"] == 1


def test_users_me_non_admin_role_is_high():
    body = json.dumps({"name": "sub", "roles": ["subscriber"], "capabilities": {"read": True}})
    out = _run("users_me_capability_leak", _client({_ME: FakeResponse(200, body)}))
    assert _sevs(out) == ["high"]


def test_users_me_200_without_caps_or_non_json_is_clean():
    assert _run("users_me_capability_leak", _client({_ME: FakeResponse(200, '{"id": 0}')})) == []
    assert _run("users_me_capability_leak", _client({_ME: FakeResponse(200, "<html>nope</html>")})) == []
    assert _run("users_me_capability_leak", _client({_ME: FakeResponse(200, "[1, 2]")})) == []


# ---------------------------------------------------------------------------
# vendor_backdoor_patterns
# ---------------------------------------------------------------------------
_README = "=== Plugin ===\nStable tag: 1.0\n" + "x" * 80


def test_vendor_backdoor_high_risk_plugin_detected():
    out = _run("vendor_backdoor_patterns",
               _client({"/wp-content/plugins/display-widgets/readme.txt": FakeResponse(200, _README)}))
    assert _sevs(out) == ["high"]
    assert out[0].extra["slug"] == "display-widgets"


def test_vendor_backdoor_nulled_plugin_is_critical():
    out = _run("vendor_backdoor_patterns",
               _client({"/wp-content/plugins/yoast-seo-nulled/readme.txt": FakeResponse(200, _README)}))
    assert _sevs(out) == ["critical"]


def test_vendor_backdoor_short_or_missing_readme_is_clean():
    c = _client({"/wp-content/plugins/display-widgets/readme.txt": FakeResponse(200, "tiny"),
                 "/wp-content/plugins/captcha-bws/readme.txt": FakeResponse(403, _README)})
    assert _run("vendor_backdoor_patterns", c) == []


# ---------------------------------------------------------------------------
# vercel_preview_url_leak
# ---------------------------------------------------------------------------
def test_vercel_preview_host_leak_is_medium():
    c = _client({"/": FakeResponse(200, '<a href="https://shop-git-main-acme.vercel.app/x">'),
                 "/sitemap.xml": FakeResponse(200, "<loc>https://stage-acme.netlify.app/</loc>")})
    out = _run("vercel_preview_url_leak", c)
    assert _sevs(out) == ["medium"]
    assert out[0].extra["hosts"] == ["shop-git-main-acme.vercel.app", "stage-acme.netlify.app"]


def test_vercel_preview_host_on_own_apex_is_ignored():
    c = _client({"/": FakeResponse(200, '<a href="https://example.com.netlify.app/x">')})
    assert _run("vercel_preview_url_leak", c) == []


def test_vercel_no_preview_hosts_is_clean():
    assert _run("vercel_preview_url_leak", _client({"/": FakeResponse(200, "<html>hi</html>")})) == []


# ---------------------------------------------------------------------------
# wc_api_key_escalation
# ---------------------------------------------------------------------------
_WP_AP = "/wp-json/wp/v2/users/me/application-passwords"
_WC_SS = "/wp-json/wc/v3/system_status"


def test_wc_api_key_escalation_advisory_when_both_gated():
    out = _run("wc_api_key_escalation", _client({_WP_AP: FakeResponse(401), _WC_SS: FakeResponse(401)}))
    assert _sevs(out) == ["low"]
    assert out[0].extra == {"wp_status": 401, "wc_status": 401}


def test_wc_api_key_escalation_wc_open_still_advisory():
    out = _run("wc_api_key_escalation", _client({_WP_AP: FakeResponse(403), _WC_SS: FakeResponse(200)}))
    assert _sevs(out) == ["low"]


def test_wc_api_key_escalation_clean_when_wp_endpoint_absent_or_no_response():
    assert _run("wc_api_key_escalation", _client({_WP_AP: FakeResponse(404), _WC_SS: FakeResponse(401)})) == []
    assert _run("wc_api_key_escalation", _client({_WP_AP: FakeResponse(401)})) == []


# ---------------------------------------------------------------------------
# wc_coupon_enum
# ---------------------------------------------------------------------------
class _SeqClient(FakeClient):
    """FakeClient whose POSTs pop scripted responses (or raise) in order."""

    def __init__(self, responses: dict, posts: list) -> None:
        super().__init__(base_url="https://example.com", responses=responses)
        self._posts = list(posts)

    async def post(self, path: str, **kwargs):
        self.requests.append(("POST", path, kwargs))
        item = self._posts.pop(0) if self._posts else None
        if isinstance(item, Exception):
            raise item
        return item


_STORE_ROOT = "/wp-json/wc/store/v1/"


def test_wc_coupon_enum_no_store_api_is_info():
    out = _run("wc_coupon_enum", _client({_STORE_ROOT: FakeResponse(404)}))
    assert _sevs(out) == ["info"]
    assert "not detected" in out[0].title


def test_wc_coupon_enum_uniform_responses_are_info():
    posts = [FakeResponse(400, '{"code":"invalid"}') for _ in range(5)]
    c = _SeqClient({_STORE_ROOT: FakeResponse(200, "{}")}, posts)
    out = asyncio.run(_fn("wc_coupon_enum")(c, _ctx()))
    assert _sevs(out) == ["info"]
    assert "uniform" in out[0].title


def test_wc_coupon_enum_divergent_responses_are_medium():
    posts = [FakeResponse(400, "x" * n) for n in (10, 10, 10, 10, 99)]
    c = _SeqClient({_STORE_ROOT: FakeResponse(200, "{}")}, posts)
    out = asyncio.run(_fn("wc_coupon_enum")(c, _ctx()))
    assert _sevs(out) == ["medium"]
    assert "oracle" in out[0].title


def test_wc_coupon_enum_unreachable_apply_endpoint_is_info():
    posts = [FakeResponse(400, "x"), RuntimeError("boom"), None, None, None]
    c = _SeqClient({_STORE_ROOT: FakeResponse(401)}, posts)
    out = asyncio.run(_fn("wc_coupon_enum")(c, _ctx()))
    assert _sevs(out) == ["info"]
    assert "unreachable" in out[0].title


# ---------------------------------------------------------------------------
# wc_hpos_namespace_drift
# ---------------------------------------------------------------------------
_FEATURES = "/wp-json/wc-admin/features"


def test_wc_hpos_enabled_list_is_low():
    body = json.dumps([{"slug": "custom-order-tables-hpos", "is_enabled": True}])
    out = _run("wc_hpos_namespace_drift", _client({_FEATURES: FakeResponse(200, body)}))
    assert _sevs(out) == ["low"]


def test_wc_hpos_enabled_dict_is_low():
    out = _run("wc_hpos_namespace_drift",
               _client({_FEATURES: FakeResponse(200, '{"custom_order_tables": true}')}))
    assert _sevs(out) == ["low"]


def test_wc_hpos_disabled_is_info():
    body = json.dumps([{"slug": "hpos", "is_enabled": False}])
    out = _run("wc_hpos_namespace_drift", _client({_FEATURES: FakeResponse(200, body)}))
    assert _sevs(out) == ["info"]
    assert "not active" in out[0].title


def test_wc_hpos_unreachable_is_info_and_bad_json_is_empty():
    out = _run("wc_hpos_namespace_drift", _client({_FEATURES: FakeResponse(404)}))
    assert _sevs(out) == ["info"]
    assert "404" in out[0].evidence
    assert _run("wc_hpos_namespace_drift", _client({}))[0].evidence.endswith("no response")
    assert _run("wc_hpos_namespace_drift", _client({_FEATURES: FakeResponse(200, "<html>")})) == []


# ---------------------------------------------------------------------------
# wc_stores_api_rate_limit_oracle (time.perf_counter is stubbed for determinism)
# ---------------------------------------------------------------------------
_CART_ADD = "/wp-json/wc/store/v1/cart/add-item"


def _stub_clock(monkeypatch, module: str, ticks: list[float]) -> None:
    import importlib

    mod = importlib.import_module(f"wpsecscan.checks.{module}")
    seq = iter(ticks)
    monkeypatch.setattr(mod, "time", SimpleNamespace(perf_counter=lambda: next(seq)))


def test_wc_stores_no_store_api_is_info():
    out = _run("wc_stores_api_rate_limit_oracle", _client({_STORE_ROOT: FakeResponse(404)}))
    assert _sevs(out) == ["info"]
    assert "not detected" in out[0].title


def test_wc_stores_fast_without_429_is_medium(monkeypatch):
    _stub_clock(monkeypatch, "wc_stores_api_rate_limit_oracle", [0.0, 0.2])
    c = _client({_STORE_ROOT: FakeResponse(200, "{}"), _CART_ADD: FakeResponse(400, "{}")})
    out = _run("wc_stores_api_rate_limit_oracle", c)
    assert _sevs(out) == ["medium"]
    assert "no rate-limit" in out[0].title


def test_wc_stores_with_429_is_info(monkeypatch):
    _stub_clock(monkeypatch, "wc_stores_api_rate_limit_oracle", [0.0, 0.2])
    c = _client({_STORE_ROOT: FakeResponse(200, "{}"), _CART_ADD: FakeResponse(429, "{}")})
    out = _run("wc_stores_api_rate_limit_oracle", c)
    assert _sevs(out) == ["info"]
    assert "rate-limited" in out[0].title


def test_wc_stores_slow_without_429_is_info(monkeypatch):
    _stub_clock(monkeypatch, "wc_stores_api_rate_limit_oracle", [0.0, 5.0])
    c = _client({_STORE_ROOT: FakeResponse(200, "{}"), _CART_ADD: FakeResponse(200, "{}")})
    assert _sevs(_run("wc_stores_api_rate_limit_oracle", c)) == ["info"]


def test_wc_stores_blocked_cart_endpoint_is_empty(monkeypatch):
    _stub_clock(monkeypatch, "wc_stores_api_rate_limit_oracle", [0.0, 0.2])
    assert _run("wc_stores_api_rate_limit_oracle", _client({_STORE_ROOT: FakeResponse(200, "{}")})) == []


# ---------------------------------------------------------------------------
# web3_wallet_connector_audit
# ---------------------------------------------------------------------------
def test_web3_wallet_plugin_and_public_rpc():
    c = _client({"/wp-content/plugins/metamask-login/readme.txt": FakeResponse(200, "r" * 60),
                 "/": FakeResponse(200, "const rpc='https://mainnet.infura.io/v3/abc';")})
    out = _run("web3_wallet_connector_audit", c)
    assert _sevs(out) == ["info", "medium"]
    assert out[0].extra["plugins"] == ["metamask-login"]
    assert out[1].extra["rpc"] == "mainnet.infura.io"


def test_web3_wallet_plugin_without_rpc_is_info_only():
    c = _client({"/wp-content/plugins/web3-login/readme.txt": FakeResponse(200, "r" * 60)})
    assert _sevs(_run("web3_wallet_connector_audit", c)) == ["info"]


def test_web3_no_wallet_plugin_is_clean_even_with_rpc_in_page():
    c = _client({"/": FakeResponse(200, "https://rpc.ankr.com/eth")})
    assert _run("web3_wallet_connector_audit", c) == []


# ---------------------------------------------------------------------------
# webhook_signing_secrets
# ---------------------------------------------------------------------------
def test_webhook_signing_secret_leak_is_critical_and_redacted():
    secret = "whsec_" + "abcdefghijklmnopqrstuvwxyz012345"
    out = _run("webhook_signing_secrets",
               _client({"/": FakeResponse(200, f'<script>var s = "{secret}";</script>')}))
    assert _sevs(out) == ["critical"]
    assert out[0].extra["secret_type"] == "Stripe webhook signing secret"
    assert secret not in out[0].evidence
    assert "***" in out[0].evidence


def test_webhook_signing_secret_named_env_var_matches_two_patterns():
    secret = "whsec_" + "abcdefghijklmnopqrstuvwxyz012345"
    out = _run("webhook_signing_secrets",
               _client({"/": FakeResponse(200, f"STRIPE_WEBHOOK_SECRET='{secret}'")}))
    assert _sevs(out) == ["critical", "critical"]


def test_webhook_signing_secret_clean_or_404():
    assert _run("webhook_signing_secrets", _client({"/": FakeResponse(200, "whsec_short")})) == []
    assert _run("webhook_signing_secrets", _client({"/": FakeResponse(404)})) == []


# ---------------------------------------------------------------------------
# woo_blocks_checkout_drift
# ---------------------------------------------------------------------------
def test_woo_blocks_store_routes_reachable_is_low():
    c = _client({"/wp-json/wc/store/v1/products": FakeResponse(200, "[]"),
                 "/wp-json/wc/store/v1/cart": FakeResponse(401)})
    out = _run("woo_blocks_checkout_drift", c)
    assert _sevs(out) == ["low"]
    assert out[0].extra["reachable_routes"] == ["/wp-json/wc/store/v1/products"]


def test_woo_blocks_no_open_routes_is_clean():
    assert _run("woo_blocks_checkout_drift", _client({"/wp-json/wc/store/v1/cart": FakeResponse(403)})) == []


# ---------------------------------------------------------------------------
# woo_subscriptions_renewal_race
# ---------------------------------------------------------------------------
def test_woo_subscriptions_fingerprinted_from_homepage():
    c = _client({"/": FakeResponse(200, '<link href="/wp-content/plugins/woocommerce-subscriptions/a.css">')})
    out = _run("woo_subscriptions_renewal_race", c)
    assert _sevs(out) == ["medium"]
    assert out[0].extra["category"] == "payments-race"


def test_woo_subscriptions_fingerprinted_from_route():
    c = _client({"/wp-json/wc/v3/subscriptions": FakeResponse(401)})
    assert _sevs(_run("woo_subscriptions_renewal_race", c)) == ["medium"]


def test_woo_subscriptions_absent_is_clean():
    c = _client({"/": FakeResponse(200, "<html></html>"),
                 "/wp-json/wc/v3/subscriptions": FakeResponse(404)})
    assert _run("woo_subscriptions_renewal_race", c) == []


# ---------------------------------------------------------------------------
# woocommerce_order_idor
# ---------------------------------------------------------------------------
_WC_V3 = "/wp-json/wc/v3/"


def test_woocommerce_order_idor_leak_is_critical_and_redacted():
    order = json.dumps({"id": 1, "billing": {"email": "alice@example.org", "phone": ""}})
    c = _client({_WC_V3: FakeResponse(200, "{}"), "/wp-json/wc/v3/orders/1": FakeResponse(200, order)})
    out = _run("woocommerce_order_idor", c)
    assert _sevs(out) == ["critical"]
    assert "1 confirmed" in out[0].title
    assert "alice@example.org" not in out[0].evidence


def test_woocommerce_order_idor_phone_only_still_counts():
    order = json.dumps({"id": 2, "billing": {"email": "", "phone": "+441234567890"}})
    c = _client({_WC_V3: FakeResponse(200, "{}"), "/wp-json/wc/v3/orders/2": FakeResponse(200, order)})
    assert _sevs(_run("woocommerce_order_idor", c)) == ["critical"]


def test_woocommerce_order_idor_clean_cases():
    # not WooCommerce
    assert _run("woocommerce_order_idor", _client({_WC_V3: FakeResponse(404)})) == []
    # auth required
    c = _client({_WC_V3: FakeResponse(200, "{}"), "*": FakeResponse(401)})
    assert _run("woocommerce_order_idor", c) == []
    # 200 but no PII / not JSON / not an object
    c = _client({_WC_V3: FakeResponse(200, "{}"),
                 "/wp-json/wc/v3/orders/1": FakeResponse(200, '{"billing": {}}'),
                 "/wp-json/wc/v3/orders/2": FakeResponse(200, "<html>"),
                 "/wp-json/wc/v3/orders/3": FakeResponse(200, "[]")})
    assert _run("woocommerce_order_idor", c) == []


# ---------------------------------------------------------------------------
# wp_cli_http_exposure
# ---------------------------------------------------------------------------
def test_wp_cli_http_exposed_is_critical():
    c = _client({"/wp-cli-server": FakeResponse(200, "WP-CLI server ready. usage: wp <command>")})
    out = _run("wp_cli_http_exposure", c)
    assert _sevs(out) == ["critical"]
    assert out[0].extra["category"] == "remote-shell"


def test_wp_cli_http_auth_gated_is_low():
    out = _run("wp_cli_http_exposure", _client({"/wp-cli/run": FakeResponse(403)}))
    assert _sevs(out) == ["low"]
    assert out[0].extra["status"] == 403


def test_wp_cli_http_generic_200_is_clean():
    assert _run("wp_cli_http_exposure", _client({"*": FakeResponse(200, "<html>Welcome</html>")})) == []


# ---------------------------------------------------------------------------
# wp_cron_cpu (time.perf_counter is stubbed for determinism)
# ---------------------------------------------------------------------------
def test_wp_cron_cpu_fast_is_info(monkeypatch):
    _stub_clock(monkeypatch, "wp_cron_cpu", [0.0, 0.1, 1.0, 1.1])
    out = _run("wp_cron_cpu", _client({"/wp-cron.php": FakeResponse(200)}))
    assert _sevs(out) == ["info"]
    assert "within tolerance" in out[0].title


def test_wp_cron_cpu_slow_is_medium(monkeypatch):
    _stub_clock(monkeypatch, "wp_cron_cpu", [0.0, 1.0, 5.0, 6.0])
    out = _run("wp_cron_cpu", _client({"/wp-cron.php": FakeResponse(200)}))
    assert _sevs(out) == ["medium"]
    assert out[0].extra["avg_response_ms"] == 1000


def test_wp_cron_cpu_very_slow_is_high(monkeypatch):
    _stub_clock(monkeypatch, "wp_cron_cpu", [0.0, 3.0, 10.0, 13.0])
    out = _run("wp_cron_cpu", _client({"/wp-cron.php": FakeResponse(200)}))
    assert _sevs(out) == ["high"]
    assert out[0].extra["avg_response_ms"] == 3000


def test_wp_cron_cpu_blocked_endpoint_is_clean():
    assert _run("wp_cron_cpu", _client({"/wp-cron.php": FakeResponse(403)})) == []


# ---------------------------------------------------------------------------
# wp_debug_display_via_rest
# ---------------------------------------------------------------------------
_POSTS = "/wp-json/wp/v2/posts"


def test_wp_debug_display_php_fatal_in_body_is_medium():
    body = "<br />Fatal error: Uncaught Exception in /var/www/html/wp-includes/rest-api.php on line 12"
    out = _run("wp_debug_display_via_rest", _client({_POSTS: FakeResponse(500, body)}))
    assert _sevs(out) == ["medium"]
    assert "Fatal error" in out[0].evidence


def test_wp_debug_display_tidy_json_error_is_clean():
    body = '{"code":"rest_invalid_json","message":"Invalid JSON body passed.","data":{"status":400}}'
    assert _run("wp_debug_display_via_rest", _client({_POSTS: FakeResponse(400, body)})) == []


def test_wp_debug_display_empty_body_is_clean():
    assert _run("wp_debug_display_via_rest", _client({_POSTS: FakeResponse(400)})) == []


# ---------------------------------------------------------------------------
# wp_mail_smtp_site_health_leak
# ---------------------------------------------------------------------------
def test_site_health_debug_dump_is_high():
    c = _client({"/wp-json/wp-site-health/v1/debug-data": FakeResponse(200, '{"smtp":{"host":"mail.example.org"}}')})
    out = _run("wp_mail_smtp_site_health_leak", c)
    assert _sevs(out) == ["high"]
    assert out[0].extra["path"] == "/wp-json/wp-site-health/v1/debug-data"


def test_site_health_auth_required_or_no_keywords_is_clean():
    c = _client({"/wp-admin/site-health.php?tab=debug": FakeResponse(403, "smtp debug"),
                 "/wp-json/health-check/v1/debug": FakeResponse(200, "<html>nothing here</html>")})
    assert _run("wp_mail_smtp_site_health_leak", c) == []


# ---------------------------------------------------------------------------
# wp_playground_sqlite
# ---------------------------------------------------------------------------
_DB = "/wp-content/database/.ht.sqlite"


def test_wp_playground_sqlite_magic_bytes_is_critical():
    blob = b"SQLite format 3\x00" + b"\x00" * 200
    out = _run("wp_playground_sqlite", _client({_DB: FakeResponse(200, content=blob)}))
    assert _sevs(out) == ["critical"]
    assert out[0].extra["file_size"] == len(blob)


def test_wp_playground_sqlite_small_nonmagic_200_is_high():
    out = _run("wp_playground_sqlite", _client({_DB: FakeResponse(200, content=b"not a database")}))
    assert _sevs(out) == ["high"]


def test_wp_playground_sqlite_detected_but_not_reachable_is_info():
    c = _client({"/": FakeResponse(200, "<meta name='generator' content='sqlite-database-integration'>"),
                 _DB: FakeResponse(404)})
    out = _run("wp_playground_sqlite", c)
    assert _sevs(out) == ["info"]
    assert out[0].extra["category"] == "database-stack"


def test_wp_playground_sqlite_nothing_detected_is_clean():
    assert _run("wp_playground_sqlite", _client({"/": FakeResponse(200, "<html></html>")})) == []


# ---------------------------------------------------------------------------
# wpconfig_hardening_audit
# ---------------------------------------------------------------------------
_DEBUG_PROBE = "/?wpsecscan-debug-probe-12345"


def test_wpconfig_theme_editor_reachable_is_medium():
    c = _client({"/wp-admin/theme-editor.php": FakeResponse(200, "<html>Edit Themes</html>")})
    out = _run("wpconfig_hardening_audit", c)
    assert _sevs(out) == ["medium"]
    assert "DISALLOW_FILE_EDIT" in out[0].title


def test_wpconfig_theme_editor_login_redirect_is_clean():
    c = _client({"/wp-admin/theme-editor.php": FakeResponse(200, "<html>wp-login.php?redirect_to=</html>")})
    assert _run("wpconfig_hardening_audit", c) == []


def test_wpconfig_debug_leak_needs_two_signals():
    two = FakeResponse(404, "Warning: foo in /wp-content/plugins/x/y.php")
    out = _run("wpconfig_hardening_audit", _client({_DEBUG_PROBE: two}))
    assert _sevs(out) == ["medium"]
    assert "PHP debug output" in out[0].title
    one = FakeResponse(404, "Warning: only one signal")
    assert _run("wpconfig_hardening_audit", _client({_DEBUG_PROBE: one})) == []


def test_wpconfig_wp_admin_http_redirect_is_high():
    c = _client({"/wp-admin/": FakeResponse(302, headers={"location": "http://example.com/wp-login.php"})})
    out = _run("wpconfig_hardening_audit", c)
    assert _sevs(out) == ["high"]
    assert "FORCE_SSL_ADMIN" in out[0].title


def test_wpconfig_wp_admin_https_redirect_is_clean():
    c = _client({"/wp-admin/": FakeResponse(302, headers={"location": "https://example.com/wp-login.php"})})
    assert _run("wpconfig_hardening_audit", c) == []


# ---------------------------------------------------------------------------
# wpcron_suspicious_jobs
# ---------------------------------------------------------------------------
_CRON = "/wp-json/wpsecscan-companion/v1/cron-jobs"


def test_wpcron_suspicious_callback_is_critical():
    body = json.dumps({"jobs": [{"hook": "daily_digest", "callback": "base64_decode", "next_run": 1}]})
    out = _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(200, body)}))
    assert _sevs(out) == ["critical"]
    assert "base64_decode" in out[0].extra["patterns"]


def test_wpcron_suspicious_hook_name_is_critical():
    body = json.dumps({"jobs": [{"hook": "wpcache_refresh", "callback": "refresh_it", "next_run": 2}]})
    out = _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(200, body)}))
    assert _sevs(out) == ["critical"]


def test_wpcron_benign_and_whitelisted_core_jobs_are_info():
    body = json.dumps({"jobs": [{"hook": "daily_digest", "callback": "send_digest_email"},
                                {"hook": "wp_update_plugins", "callback": "eval"}]})
    out = _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(200, body)}))
    assert _sevs(out) == ["info"]
    assert out[0].title.startswith("2 wp-cron jobs")


def test_wpcron_missing_companion_or_bad_payload_is_clean():
    assert _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(404)})) == []
    assert _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(200, "<html>")})) == []
    assert _run("wpcron_suspicious_jobs", _client({_CRON: FakeResponse(200, "[1]")})) == []


# ---------------------------------------------------------------------------
# xmlrpc_amplification
# ---------------------------------------------------------------------------
def _multicall_request_bytes() -> int:
    import importlib

    # ``wpsecscan.checks.xmlrpc_amplification`` the attribute is the check
    # function (re-exported), so resolve the module explicitly.
    mod = importlib.import_module("wpsecscan.checks.xmlrpc_amplification")
    payload = mod._PAYLOAD_TEMPLATE.format(calls="\n".join([mod._CALL] * 50))
    return len(payload.encode("utf-8"))


@pytest.mark.parametrize(("factor", "severity"), [(6, "low"), (30, "medium"), (150, "high")])
def test_xmlrpc_amplification_severity_by_ratio(factor, severity):
    size = _multicall_request_bytes() * factor
    c = _client({"/xmlrpc.php": FakeResponse(200, content=b"x" * size)})
    out = _run("xmlrpc_amplification", c)
    assert _sevs(out) == [severity]
    assert out[0].extra["amplification_ratio"] == pytest.approx(factor, rel=0.01)


def test_xmlrpc_amplification_small_response_or_disabled_is_clean():
    small = _client({"/xmlrpc.php": FakeResponse(200, content=b"x" * 100)})
    assert _run("xmlrpc_amplification", small) == []
    assert _run("xmlrpc_amplification", _client({"/xmlrpc.php": FakeResponse(403)})) == []


# ---------------------------------------------------------------------------
# yarn_pnpm_lock_audit
# ---------------------------------------------------------------------------
_YARN_HDR = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n"


def test_yarn_lock_exposed_is_medium():
    out = _run("yarn_pnpm_lock_audit", _client({"/yarn.lock": FakeResponse(200, _YARN_HDR)}))
    assert _sevs(out) == ["medium"]
    assert out[0].title.startswith("yarn.lock exposed")


def test_pnpm_lock_exposed_is_medium():
    body = "lockfileVersion: '6.0'\n\npackages:\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n"
    out = _run("yarn_pnpm_lock_audit", _client({"/pnpm-lock.yaml": FakeResponse(200, body)}))
    assert _sevs(out) == ["medium"]
    assert out[0].title.startswith("pnpm-lock.yaml exposed")


def test_yarn_lock_registry_token_is_critical():
    body = (_YARN_HDR + 'resolved "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz?token=abcdefghijklmnopqrst1234"\n')
    out = _run("yarn_pnpm_lock_audit", _client({"/yarn.lock": FakeResponse(200, body)}))
    assert _sevs(out) == ["medium", "critical"]
    assert "token" in out[1].title.lower()


def test_lockfile_html_soft_404_and_tiny_bodies_are_clean():
    c = _client({"/yarn.lock": FakeResponse(200, "<html>" + "x" * 100 + "</html>"),
                 "/pnpm-lock.yaml": FakeResponse(200, "tiny")})
    assert _run("yarn_pnpm_lock_audit", c) == []
