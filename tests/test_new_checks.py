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


# ============================== item 1 — WC Stripe escalation ==============================

def test_stripe_pk_live_escalates_to_medium_on_woocommerce():
    """Item 1: pk_live found alongside WooCommerce markers should be medium,
    not the default low — it's a real billing-impact key."""
    from wpsecscan.checks.secret_leak import check
    fake = "pk_" + "live_" + "ABCdef1234567890ABCdef1234"
    body = (
        f"window.wc_add_to_cart_params = {{stripe: '{fake}'}};\n"
        "<script src='/wp-content/plugins/woocommerce-gateway-stripe/...'></script>"
    )
    client = FakeClient(responses={"/checkout/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    pks = [f for f in findings if "Stripe live publishable" in f.title]
    assert pks, "expected at least one Stripe pk_live finding"
    assert pks[0].severity == "medium", f"expected medium on WC page, got {pks[0].severity}"


def test_stripe_pk_live_stays_low_off_woocommerce():
    from wpsecscan.checks.secret_leak import check
    fake = "pk_" + "live_" + "ABCdef1234567890ABCdef1234"
    body = f"var stripe = '{fake}';"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    pks = [f for f in findings if "Stripe live publishable" in f.title]
    assert pks
    assert pks[0].severity == "low"


# ============================== item 5 — extended secret patterns ==============================

def test_secret_leak_flags_mapbox_secret_token():
    from wpsecscan.checks.secret_leak import check
    body = ('TOKEN = "sk.eyJ1IjoiYWJjZGVmZ2hpamtsbW5vcCJ9'
            '.abcdef0123456789abcdef0123456789"')
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    hits = [f for f in findings if "Mapbox secret token" in f.title]
    assert hits and hits[0].severity == "critical"


def test_secret_leak_flags_algolia_admin_key_with_context():
    from wpsecscan.checks.secret_leak import check
    body = ("algolia.init({adminKey: '0123456789abcdef0123456789abcdef'});")
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("Algolia admin API key" in f.title for f in findings)


def test_secret_leak_algolia_pattern_requires_context():
    """A bare 32-char hex string with no algolia mention should NOT fire."""
    from wpsecscan.checks.secret_leak import check
    body = "<p>md5: 0123456789abcdef0123456789abcdef</p>"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert not any("Algolia" in f.title for f in findings)


def test_secret_leak_flags_sentry_dsn():
    from wpsecscan.checks.secret_leak import check
    body = ('Sentry.init({dsn: "https://abcdef0123456789abcdef0123456789'
            '@o123456.ingest.us.sentry.io/4500000000000000"});')
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("Sentry DSN" in f.title for f in findings)


def test_secret_leak_flags_meilisearch_master_key_with_context():
    from wpsecscan.checks.secret_leak import check
    body = ('const meili = new MeiliSearch({'
            'host: "https://meili.example.com",'
            'apiKey: "abcDEF123456ghiJKL789mnoPQR012stu"});')
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("MeiliSearch master key" in f.title for f in findings)


def test_secret_leak_flags_new_relic_browser_key():
    from wpsecscan.checks.secret_leak import check
    body = (
        '<script>window.NREUM||(NREUM={});NREUM.info='
        '{"beacon":"bam.nr-data.net","licenseKey":"NRBR-ABC123def456ghi789jkl"};'
        'window.newrelic=NREUM;</script>'
    )
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("New Relic" in f.title for f in findings)


# ============================== item 6 — referenced_buckets ==============================

def test_referenced_buckets_extracts_s3_url():
    from wpsecscan.checks.referenced_buckets import _BUCKET_PATTERNS
    body = '<img src="https://my-prod-uploads.s3.us-east-1.amazonaws.com/photo.jpg">'
    for provider, pat in _BUCKET_PATTERNS:
        if provider == "s3":
            m = pat.search(body)
            assert m, "expected S3 regex to match"
            assert m.group(1) == "my-prod-uploads"
            break


def test_referenced_buckets_extracts_gcs_url():
    from wpsecscan.checks.referenced_buckets import _BUCKET_PATTERNS
    body = '<script src="https://storage.googleapis.com/my-static-site/app.js"></script>'
    for provider, pat in _BUCKET_PATTERNS:
        if provider == "gcs":
            m = pat.search(body)
            assert m and m.group(1) == "my-static-site"
            break


def test_referenced_buckets_extracts_r2_dev_url():
    from wpsecscan.checks.referenced_buckets import _BUCKET_PATTERNS
    body = '<img src="https://my-images.r2.dev/cat.png">'
    for provider, pat in _BUCKET_PATTERNS:
        if provider == "r2":
            m = pat.search(body)
            assert m and m.group(1) == "my-images"
            break


def test_referenced_buckets_extracts_do_spaces_url():
    from wpsecscan.checks.referenced_buckets import _BUCKET_PATTERNS
    body = 'background-image: url("https://my-cdn.nyc3.cdn.digitaloceanspaces.com/hero.jpg");'
    for provider, pat in _BUCKET_PATTERNS:
        if provider == "spaces":
            m = pat.search(body)
            assert m and m.group(1) == "my-cdn"
            break


def test_referenced_buckets_listing_detector_recognises_s3_xml():
    from wpsecscan.checks.referenced_buckets import _is_listing_response
    body = b'<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult><Contents>...'
    assert _is_listing_response("s3", 200, body) is True
    assert _is_listing_response("s3", 403, body) is False
    assert _is_listing_response("s3", 200, b"<html>not a bucket</html>") is False


def test_referenced_buckets_clean_when_no_buckets_referenced():
    """Item 6: with no bucket URLs in the page, the check emits one info finding
    instead of crashing or returning empty."""
    import asyncio as _asyncio
    from wpsecscan.checks.referenced_buckets import check
    client = FakeClient(responses={"/": FakeResponse(text="<html>plain page</html>")})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert findings, "expected at least one info finding even when no buckets are referenced"
    assert any("No cloud-bucket URLs" in f.title for f in findings)


# ============================== item 2 — cloudflare_origin_leak helpers ==============================

def test_cf_origin_leak_recognises_cf_ip():
    from wpsecscan.checks.cloudflare_origin_leak import _ip_in_cf
    assert _ip_in_cf("104.16.0.1") is True       # in 104.16.0.0/13
    assert _ip_in_cf("172.64.32.99") is True     # in 172.64.0.0/13
    assert _ip_in_cf("1.2.3.4") is False
    assert _ip_in_cf("8.8.8.8") is False
    assert _ip_in_cf("not-an-ip") is False


def test_cf_origin_leak_apex_trim():
    from wpsecscan.checks.cloudflare_origin_leak import _apex
    assert _apex("foo.com") == "foo.com"
    assert _apex("www.foo.com") == "foo.com"
    assert _apex("blog.staging.foo.co.uk") == "foo.co.uk"
    assert _apex("api.bar.com.au") == "bar.com.au"


# ============================== check registry ==============================

def test_all_new_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = [c[0] for c in ALL_CHECKS]
    for required in ("rest_api", "cors", "js_libraries", "secret_leak",
                      "referenced_buckets", "cloudflare_origin_leak",
                      "crlf_location_injection", "host_header_validation",
                      "woocommerce_storefront", "page_builder_cve",
                      "wp_fork_detection"):
        assert required in ids, f"check {required!r} not registered in ALL_CHECKS"


# ============================== items 19 + 20 — fork detection ==============================

def test_wp_fork_detects_classicpress():
    import asyncio as _asyncio
    from wpsecscan.checks.wp_fork_detection import check
    cp_root = FakeResponse(
        status_code=200,
        text='{"name":"My Site","description":"Just another ClassicPress site"}',
    )
    client = FakeClient(responses={"/wp-json/": cp_root})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("classicpress" in f.title.lower() for f in findings)
    assert ctx["shared"].get("wp_fork") == "classicpress"


def test_wp_fork_detects_headless_next():
    import asyncio as _asyncio
    from wpsecscan.checks.wp_fork_detection import check
    home = FakeResponse(
        status_code=200,
        text='<html><script>self.__NEXT_DATA__={};</script><link href="/_next/static/x.css"></html>',
    )
    client = FakeClient(responses={"/": home})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("headless-next" in f.title for f in findings)


def test_wp_fork_default_to_vanilla():
    import asyncio as _asyncio
    from wpsecscan.checks.wp_fork_detection import check
    client = FakeClient(responses={"/": FakeResponse(text="<html>vanilla</html>")})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("vanilla WordPress" in f.title for f in findings)
    assert ctx["shared"].get("wp_fork") == "wordpress"


# ============================== item 18 — page builder CVE ==============================

def test_page_builder_cve_flags_bricks():
    import asyncio as _asyncio
    from wpsecscan.checks.page_builder_cve import check
    body = '<html><meta name="generator" content="Bricks 1.9.5"><body class="brxe-section"></body></html>'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("Bricks" in f.title for f in findings)


def test_page_builder_cve_flags_divi():
    import asyncio as _asyncio
    from wpsecscan.checks.page_builder_cve import check
    body = '<html><body><div class="et_pb_section et_pb_section_0">divi</div></body></html>'
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("Divi" in f.title for f in findings)


def test_page_builder_cve_none_when_clean():
    import asyncio as _asyncio
    from wpsecscan.checks.page_builder_cve import check
    body = "<html><body>vanilla site</body></html>"
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("none detected" in f.title.lower() for f in findings)


# ============================== items 15 + 16 — WC storefront ==============================

def test_wc_storefront_skips_when_no_wc_detected():
    import asyncio as _asyncio
    from wpsecscan.checks.woocommerce_storefront import check
    client = FakeClient(responses={
        "/": FakeResponse(text="<html>not a WP site</html>"),
        "/wp-json/wc/store/v1/cart": FakeResponse(status_code=404),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("not detected" in f.title for f in findings)


def test_wc_storefront_flags_fragments_cacheable():
    """If the fragments endpoint returns Cache-Control: public, max-age=...
    the check fires high."""
    import asyncio as _asyncio
    from wpsecscan.checks.woocommerce_storefront import check
    cart = FakeResponse(status_code=200, text='{"items":[]}')
    apply = FakeResponse(status_code=200, text='{"fragments":{}}')
    frag = FakeResponse(
        status_code=200,
        text='{"fragments":{}}',
        headers={"cache-control": "public, max-age=3600"},
    )
    client = FakeClient(responses={
        "/wp-json/wc/store/v1/cart": cart,
        "/?wc-ajax=apply_coupon": apply,
        "/?wc-ajax=get_refreshed_fragments": frag,
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("fragments endpoint is cacheable" in f.title for f in findings)


def test_wc_storefront_flags_coupon_enumeration():
    import asyncio as _asyncio
    from wpsecscan.checks.woocommerce_storefront import check
    cart = FakeResponse(status_code=200, text='{"items":[]}')
    apply = FakeResponse(status_code=200, text='{"error":"invalid"}')
    frag = FakeResponse(status_code=200, text='{"fragments":{}}',
                          headers={"cache-control": "no-store, private"})
    client = FakeClient(responses={
        "/wp-json/wc/store/v1/cart": cart,
        "/?wc-ajax=apply_coupon": apply,
        "/?wc-ajax=get_refreshed_fragments": frag,
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("unthrottled enumeration" in f.title for f in findings)


# ============================== item 7 — Host-header validation ==============================

def test_host_header_validation_flags_spoofed_acceptance():
    import asyncio as _asyncio
    from wpsecscan.checks.host_header_validation import check
    vulnerable_resp = FakeResponse(
        status_code=200,
        text="<html><a href='/wp-admin/'>WordPress login</a></html>",
    )
    client = FakeClient(responses={"*": vulnerable_resp})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("DNS-rebinding" in f.title for f in findings)


def test_host_header_validation_clean_when_421_returned():
    import asyncio as _asyncio
    from wpsecscan.checks.host_header_validation import check
    safe = FakeResponse(status_code=421, text="Misdirected Request")
    client = FakeClient(responses={"*": safe})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("clean" in f.title.lower() for f in findings)


# ============================== item 4 — CRLF Location injection ==============================

def test_crlf_location_injection_flags_set_cookie_followthrough():
    """If the server reflects the CRLF payload into a Set-Cookie follower
    header, the check should fire high."""
    import asyncio as _asyncio
    from wpsecscan.checks.crlf_location_injection import check
    # Build a 302 response with the injected Set-Cookie present.
    vulnerable_resp = FakeResponse(
        status_code=302,
        headers={
            "location": "https://example.com/",
            "set-cookie": "wpsecscan-crlf-probe=1; Path=/",
        },
    )
    # Every probed endpoint returns the same vulnerable response.
    client = FakeClient(responses={"*": vulnerable_resp})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    high = [f for f in findings if f.severity == "high"]
    assert high, "expected at least one high finding when Set-Cookie reflects the probe"
    assert "CRLF" in high[0].title


def test_crlf_location_injection_clean_path():
    import asyncio as _asyncio
    from wpsecscan.checks.crlf_location_injection import check
    # 302 with a clean Location and no Set-Cookie.
    safe = FakeResponse(status_code=302, headers={"location": "https://example.com/"})
    client = FakeClient(responses={"*": safe})
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = _asyncio.run(check(client, ctx))
    assert any("clean" in f.title.lower() for f in findings)


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
