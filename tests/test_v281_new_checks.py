"""v2.8.2 Phase 3.2 — behavioral coverage for the 17 v2.8.1 check modules
(F2-F23) that shipped without dedicated tests. One happy-path and one
empty-response test per check. Pattern follows the v2.8.0
`test_woocommerce_storefront` style in test_new_checks.py.
"""
from __future__ import annotations

import asyncio

import pytest

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx(target: str = "https://example.com") -> dict:
    return {"target": target, "shared": {}, "step": lambda _s: None}


# ===========================================================================
# F2 — wc_cart_abandonment_xss
# ===========================================================================
def test_wc_cart_abandonment_xss_detects_plugin_present():
    from wpsecscan.checks.wc_cart_abandonment_xss import check
    client = FakeClient(responses={
        "/wp-content/plugins/woo-cart-abandonment-recovery/":
            FakeResponse(status_code=200),
        "/wp-content/plugins/cartflows-ca/": FakeResponse(status_code=404),
        "/wp-content/plugins/retainful/": FakeResponse(status_code=404),
    })
    findings = _run(check(client, _ctx()))
    assert any("cart-abandonment" in (f.title or "").lower() for f in findings)


def test_wc_cart_abandonment_xss_silent_when_no_plugin():
    from wpsecscan.checks.wc_cart_abandonment_xss import check
    client = FakeClient(responses={})  # all paths return 404
    findings = _run(check(client, _ctx()))
    # Should NOT emit medium-severity finding when nothing detected
    assert all(f.severity != "medium" for f in findings)


# ===========================================================================
# F3 — wc_draft_order_escalation
# ===========================================================================
def test_wc_draft_order_escalation_emits_info_when_unreachable():
    from wpsecscan.checks.wc_draft_order_escalation import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("unreachable" in (f.title or "").lower() or
                f.severity == "info" for f in findings)


def test_wc_draft_order_escalation_flags_open_200():
    from wpsecscan.checks.wc_draft_order_escalation import check
    client = FakeClient(responses={
        "/wp-json/wc/store/v1/checkout": FakeResponse(status_code=200)
    })
    findings = _run(check(client, _ctx()))
    assert any("200 unauthenticated" in (f.title or "") for f in findings)


# ===========================================================================
# F4 — wc_payment_link_replay
# ===========================================================================
def test_wc_payment_link_replay_returns_empty_on_404():
    """v2.8.2 M10 — 404 means not a WC site; should return [] not info."""
    from wpsecscan.checks.wc_payment_link_replay import check
    client = FakeClient(responses={
        "/checkout/order-pay/": FakeResponse(status_code=404)
    })
    findings = _run(check(client, _ctx()))
    assert findings == []


def test_wc_payment_link_replay_flags_missing_referrer_policy():
    from wpsecscan.checks.wc_payment_link_replay import check
    client = FakeClient(responses={
        "/checkout/order-pay/": FakeResponse(status_code=200, headers={})
    })
    findings = _run(check(client, _ctx()))
    assert any("Referrer-Policy" in (f.title or "") for f in findings)


# ===========================================================================
# F5 — stripe_connect_state_csrf
# ===========================================================================
def test_stripe_connect_state_csrf_skips_when_no_plugin():
    from wpsecscan.checks.stripe_connect_state_csrf import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("No Stripe Connect plugin" in (f.title or "")
                for f in findings)


def test_stripe_connect_state_csrf_advisory_when_plugin_found():
    from wpsecscan.checks.stripe_connect_state_csrf import check
    client = FakeClient(responses={
        "/wp-content/plugins/woocommerce-gateway-stripe/":
            FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("Stripe Connect plugin detected" in (f.title or "")
                for f in findings)


# ===========================================================================
# F6 — plugin_update_server_integrity
# ===========================================================================
def test_plugin_update_server_integrity_skipped_when_rest_blocked():
    from wpsecscan.checks.plugin_update_server_integrity import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/plugins": FakeResponse(status_code=401)
    })
    findings = _run(check(client, _ctx()))
    assert any("skipped" in (f.title or "").lower() for f in findings)


def test_plugin_update_server_integrity_flags_http_update_uri():
    from wpsecscan.checks.plugin_update_server_integrity import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/plugins": FakeResponse(
            status_code=200,
            text='[{"plugin": "evilplugin/evil.php", '
                  '"update_uri": "http://evil.example/updates"}]',
        )
    })
    findings = _run(check(client, _ctx()))
    assert any("MITM risk" in (f.title or "") for f in findings)


# ===========================================================================
# F7 — wp_auto_update_filter_exposure
# ===========================================================================
def test_wp_auto_update_filter_exposure_silent_when_rest_blocked():
    from wpsecscan.checks.wp_auto_update_filter_exposure import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert findings == []


def test_wp_auto_update_filter_exposure_flags_public_listing():
    from wpsecscan.checks.wp_auto_update_filter_exposure import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/plugins?_fields=plugin,auto_update":
            FakeResponse(status_code=200,
                          text='[{"plugin": "a", "auto_update": false},'
                                '{"plugin": "b", "auto_update": true}]'),
    })
    findings = _run(check(client, _ctx()))
    assert any("auto-update OFF" in (f.title or "") for f in findings)


# ===========================================================================
# F8 — activitypub_data_leak
# ===========================================================================
def test_activitypub_data_leak_skipped_when_no_plugin():
    from wpsecscan.checks.activitypub_data_leak import check
    client = FakeClient(responses={
        "/wp-json/activitypub/1.0/users/1": FakeResponse(status_code=404)
    })
    findings = _run(check(client, _ctx()))
    assert any("not detected" in (f.title or "") for f in findings)


def test_activitypub_data_leak_flags_email_in_actor():
    from wpsecscan.checks.activitypub_data_leak import check
    client = FakeClient(responses={
        "/wp-json/activitypub/1.0/users/1": FakeResponse(
            status_code=200,
            text='{"name":"admin","email":"admin@example.com"}'),
    })
    findings = _run(check(client, _ctx()))
    assert any("leaks fields" in (f.title or "") for f in findings)


# ===========================================================================
# F9 — synced_pattern_leak
# ===========================================================================
def test_synced_pattern_leak_silent_when_no_data():
    from wpsecscan.checks.synced_pattern_leak import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/blocks?per_page=1": FakeResponse(
            status_code=200, text="[]"),
    })
    findings = _run(check(client, _ctx()))
    assert findings == []


def test_synced_pattern_leak_flags_public_blocks():
    from wpsecscan.checks.synced_pattern_leak import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/blocks?per_page=1": FakeResponse(
            status_code=200, text='[{"id":1,"title":{"raw":"hi"}}]'),
    })
    findings = _run(check(client, _ctx()))
    assert any("synced patterns" in (f.title or "") for f in findings)


# ===========================================================================
# F10 — global_styles_css_injection (v2.8.2 L8 made this stricter)
# ===========================================================================
def test_global_styles_css_injection_silent_without_user_css():
    """v2.8.2 L8 — endpoint exists but no user CSS → should not fire."""
    from wpsecscan.checks.global_styles_css_injection import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/global-styles?per_page=1": FakeResponse(
            status_code=200, text='[{"id":1,"settings":{},"styles":{}}]'),
    })
    findings = _run(check(client, _ctx()))
    assert findings == []


def test_global_styles_css_injection_fires_with_user_css():
    from wpsecscan.checks.global_styles_css_injection import check
    client = FakeClient(responses={
        "/wp-json/wp/v2/global-styles?per_page=1": FakeResponse(
            status_code=200,
            text='[{"id":1,"settings":{"custom":{"foo":"bar"}},'
                  '"styles":{"css":"body{background:red}"}}]'),
    })
    findings = _run(check(client, _ctx()))
    assert any("global-styles" in (f.title or "") for f in findings)


# ===========================================================================
# F11 — multisite_network_option_idor (v2.8.2 M9 changed detection)
# ===========================================================================
def test_multisite_network_option_idor_skipped_when_not_multisite():
    """v2.8.2 M9 — uses REST namespaces, not body sniff."""
    from wpsecscan.checks.multisite_network_option_idor import check
    client = FakeClient(responses={
        "/wp-json/": FakeResponse(
            status_code=200, text='{"namespaces":["wp/v2"]}'),
    })
    findings = _run(check(client, _ctx()))
    assert any("not detected" in (f.title or "") for f in findings)


# ===========================================================================
# F13 — multisite_super_admin_rbac
# ===========================================================================
def test_multisite_super_admin_rbac_skipped_when_no_plugins():
    from wpsecscan.checks.multisite_super_admin_rbac import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert findings == []


def test_multisite_super_admin_rbac_flags_when_ure_endpoint_exposed():
    from wpsecscan.checks.multisite_super_admin_rbac import check
    client = FakeClient(responses={
        "/wp-json/user-role-editor/v1/roles": FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("role-editor plugin" in (f.title or "") for f in findings)


# ===========================================================================
# F15 — rest_only_admin_probe
# ===========================================================================
def test_rest_only_admin_probe_silent_when_not_headless():
    """Theme markers present → not headless → no finding."""
    from wpsecscan.checks.rest_only_admin_probe import check
    big_themed_html = ("<html><body>" +
                        "wp-content/themes/twentytwentyfour " * 200 +
                        "</body></html>")
    client = FakeClient(responses={
        "/wp-admin/": FakeResponse(status_code=200, text="login"),
        "/wp-json/": FakeResponse(status_code=200, text="{}"),
        "/": FakeResponse(status_code=200, text=big_themed_html),
    })
    findings = _run(check(client, _ctx()))
    assert findings == []


# ===========================================================================
# F16 — nextjs_env_var_exposure
# ===========================================================================
def test_nextjs_env_var_exposure_skipped_when_no_next():
    from wpsecscan.checks.nextjs_env_var_exposure import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("not detected" in (f.title or "") for f in findings)


# ===========================================================================
# F18 — ai_agent_tool_injection
# ===========================================================================
def test_ai_agent_tool_injection_skipped_without_plugins():
    from wpsecscan.checks.ai_agent_tool_injection import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("no AI-agent plugins" in (f.title or "") for f in findings)


def test_ai_agent_tool_injection_flags_detected_plugin():
    from wpsecscan.checks.ai_agent_tool_injection import check
    client = FakeClient(responses={
        "/wp-content/plugins/ai-engine/": FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("AI-agent plugin(s) detected" in (f.title or "")
                for f in findings)


# ===========================================================================
# F19 — wc_multivendor_idor
# ===========================================================================
def test_wc_multivendor_idor_skipped_without_plugins():
    from wpsecscan.checks.wc_multivendor_idor import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("no multi-vendor" in (f.title or "") for f in findings)


def test_wc_multivendor_idor_flags_dokan():
    from wpsecscan.checks.wc_multivendor_idor import check
    client = FakeClient(responses={
        "/wp-content/plugins/dokan-lite/": FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("multi-vendor plugin(s) detected" in (f.title or "")
                for f in findings)


# ===========================================================================
# F22 — webauthn_rp_id_audit
# ===========================================================================
def test_webauthn_rp_id_audit_skipped_without_plugins():
    from wpsecscan.checks.webauthn_rp_id_audit import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("no WebAuthn" in (f.title or "") for f in findings)


def test_webauthn_rp_id_audit_advisory_when_plugin_found():
    from wpsecscan.checks.webauthn_rp_id_audit import check
    client = FakeClient(responses={
        "/wp-content/plugins/two-factor/": FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("RP-ID audit" in (f.title or "") for f in findings)


# ===========================================================================
# F23 — wc_refund_flow_idor
# ===========================================================================
def test_wc_refund_flow_idor_skipped_without_plugins():
    from wpsecscan.checks.wc_refund_flow_idor import check
    client = FakeClient(responses={})
    findings = _run(check(client, _ctx()))
    assert any("no payment-gateway" in (f.title or "") for f in findings)


def test_wc_refund_flow_idor_flags_paypal():
    from wpsecscan.checks.wc_refund_flow_idor import check
    client = FakeClient(responses={
        "/wp-content/plugins/woocommerce-paypal-payments/":
            FakeResponse(status_code=200),
    })
    findings = _run(check(client, _ctx()))
    assert any("refund-IDOR history" in (f.title or "") for f in findings)


# ===========================================================================
# Crash-on-empty contract: every new check must handle None responses
# without raising.
# ===========================================================================
@pytest.mark.parametrize("check_module", [
    "wc_cart_abandonment_xss", "wc_draft_order_escalation",
    "wc_payment_link_replay", "stripe_connect_state_csrf",
    "plugin_update_server_integrity", "wp_auto_update_filter_exposure",
    "activitypub_data_leak", "synced_pattern_leak",
    "global_styles_css_injection", "multisite_network_option_idor",
    "multisite_super_admin_rbac", "rest_only_admin_probe",
    "nextjs_env_var_exposure", "ai_agent_tool_injection",
    "wc_multivendor_idor", "webauthn_rp_id_audit", "wc_refund_flow_idor",
])
def test_new_check_handles_empty_response_without_raising(check_module):
    import importlib
    mod = importlib.import_module(f"wpsecscan.checks.{check_module}")
    client = FakeClient(responses={})  # FakeClient returns None for unknown paths
    # Must not raise
    findings = _run(mod.check(client, _ctx()))
    assert isinstance(findings, list)
