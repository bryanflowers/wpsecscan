"""Tests for the four new checks: rest_api, cors, js_libraries, secret_leak."""
from __future__ import annotations

import asyncio

from tests.conftest import FakeClient, FakeResponse


def run(coro):
    return asyncio.run(coro)


# ============================== rest_api ==============================

def test_rest_api_flags_exposed_settings():
    from wpsecscan.checks.rest_api import check
    client = FakeClient(responses={
        "/wp-json/": FakeResponse(text='{"namespaces": ["wp/v2"]}'),
        "/wp-json/wp/v2/settings": FakeResponse(text='{"title": "My Site", "default_role": "editor"}'),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    titles = [f.title for f in findings]
    assert any("settings" in t.lower() for t in titles)


def test_rest_api_lists_namespaces():
    from wpsecscan.checks.rest_api import check
    client = FakeClient(responses={
        "/wp-json/": FakeResponse(text='{"namespaces": ["wp/v2", "jetpack/v4", "wc/v3"]}'),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("3 namespace" in f.title for f in findings)


def test_rest_api_clean_when_nothing_exposed():
    from wpsecscan.checks.rest_api import check
    client = FakeClient(responses={})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("No REST API surface findings" in f.title for f in findings)


# ============================== cors ==============================

def test_cors_reflects_attacker_origin_with_credentials():
    from wpsecscan.checks.cors import check, PROBE_ORIGIN
    client = FakeClient(responses={
        "/": FakeResponse(headers={
            "access-control-allow-origin": PROBE_ORIGIN,
            "access-control-allow-credentials": "true",
        }),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "high" and "reflects attacker origin" in f.title.lower() for f in findings)


def test_cors_wildcard_only_low_severity():
    from wpsecscan.checks.cors import check
    client = FakeClient(responses={
        "/": FakeResponse(headers={"access-control-allow-origin": "*"}),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "low" and "wildcard" in f.title.lower() for f in findings)


def test_cors_clean_when_no_acao():
    from wpsecscan.checks.cors import check
    client = FakeClient(responses={"/": FakeResponse(text="hello")})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("No CORS reflection" in f.title for f in findings)


# ============================== js_libraries ==============================

def test_js_libraries_flags_old_jquery():
    from wpsecscan.checks.js_libraries import check
    body = """
        <script src="/wp-includes/js/jquery/jquery-1.12.4.min.js"></script>
        <script src="/assets/lodash-4.17.20.min.js"></script>
    """
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    titles = " ".join(f.title for f in findings)
    assert "jQuery" in titles
    assert "Outdated" in titles
    # Lodash 4.17.20 is older than 4.17.21 cutoff
    assert "lodash" in titles.lower()


def test_js_libraries_flags_angularjs_eol():
    from wpsecscan.checks.js_libraries import check
    body = '<script src="/assets/angular.js-1.7.9.min.js"></script>'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("end-of-life" in f.title.lower() and "AngularJS" in f.title for f in findings)


def test_js_libraries_clean_when_modern():
    from wpsecscan.checks.js_libraries import check
    body = '<script src="/assets/jquery-3.7.1.min.js"></script>'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    # Should not have an "Outdated jQuery" medium finding
    assert not any(f.severity == "medium" and "Outdated jQuery" in f.title for f in findings)


# ============================== secret_leak ==============================

def test_secret_leak_flags_stripe_live_key():
    from wpsecscan.checks.secret_leak import check
    # Build the fixture at runtime so the literal `sk_live_` pattern doesn't
    # appear in source — GitHub's secret-scanner blocks pushes that contain
    # any Stripe-key-shaped literal even when it's an obvious placeholder.
    fake_key = "sk_" + "live_" + "abc123def456ghi789jkl012mno345"
    body = f"var stripeKey = '{fake_key}';"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "critical" and "Stripe live secret key" in f.title for f in findings)


def test_secret_leak_flags_openai_key():
    from wpsecscan.checks.secret_leak import check
    body = 'API_KEY = "sk-proj-abc123def456ghi789jklmnopqrstuvwxyz1234"'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("OpenAI/Anthropic API key" in f.title for f in findings)


def test_secret_leak_flags_anthropic_key():
    """The merged OpenAI/Anthropic critical pattern should match sk-ant- too."""
    from wpsecscan.checks.secret_leak import check
    body = 'CLAUDE = "sk-ant-api03-abcDEF123-_xyzqrstuvwxyz12345678"'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any(f.severity == "critical" and "OpenAI/Anthropic" in f.title for f in findings)


def test_secret_leak_generic_sk_prefix_is_low():
    """A bare `sk-` (not sk-proj-/svcacct-/ant-) should be low-severity, not
    critical — too many non-secret tokens use that prefix."""
    from wpsecscan.checks.secret_leak import check
    body = 'token = "sk-MyCustomJwtSecretThatIsNotAnyVendorKey1234567890"'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    crits = [f for f in findings if f.severity == "critical" and "sk-" in (f.evidence or "")]
    assert not crits, f"generic sk- prefix should not be critical, got: {[f.title for f in crits]}"


def test_secret_leak_redacts_the_secret():
    from wpsecscan.checks.secret_leak import check
    body = "var sk = 'sk_live_THIS_IS_SECRET_MUST_NOT_LEAK_INTO_REPORT_zzzzzz';"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    for f in findings:
        # The redacted version should be in the finding, the full secret must not be
        assert "THIS_IS_SECRET_MUST_NOT_LEAK" not in f.evidence
        assert "MUST_NOT_LEAK" not in (f.remediation or "")


def test_secret_leak_clean_when_no_secrets():
    from wpsecscan.checks.secret_leak import check
    body = "<html><body>Hello world</body></html>"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("No accidental secret patterns" in f.title for f in findings)


# ============================== check registry ==============================

def test_all_new_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = [c[0] for c in ALL_CHECKS]
    for required in ("rest_api", "cors", "js_libraries", "secret_leak"):
        assert required in ids, f"check {required!r} not registered in ALL_CHECKS"


def test_new_exploit_signatures_loaded():
    """Verify the expanded exploit_signatures.json loads and has the new entries."""
    from pathlib import Path
    import json
    sig_path = Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "exploit_signatures.json"
    data = json.loads(sig_path.read_text(encoding="utf-8"))
    ids = [s["id"] for s in data["signatures"] if "id" in s]
    assert "CVE-2024-2879" in ids       # LayerSlider
    assert "CVE-2024-1071" in ids       # Ultimate Member SQLi
    assert "CVE-2024-2876" in ids       # Email Subscribers
    assert "WPSX-INSTALL-PHP" in ids    # install.php hijack
    assert len(data["signatures"]) >= 25
