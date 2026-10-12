"""v2.9.1 W11 (lane B) -- offline tests for registered checks that had zero
test references.

Slice: the middle third (positions 30..59 of 91) of the sorted list of
registered check ids with no reference (id or module name) under tests/**
at the time of writing. Every check here is passive (aggressive=False).

Approach: each check's ``check(client, ctx)`` is driven with a scripted
async client. No socket is ever opened: ``wpsecscan.http.Client`` and
``httpx.AsyncClient`` / ``httpx.Client`` are replaced by guards, name
resolution is blocked, ``asyncio.sleep`` is a no-op and HOME is a tmp dir.

Per check: a sweep asserting it returns a list on benign / empty / failed
responses, plus a triggering case and a non-triggering case asserting
severity / title / extra where the logic is simple.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import shutil
import socket

import httpx
import pytest

from wpsecscan.checks import ALL_CHECKS
from wpsecscan.models import Finding

TARGET = "https://example.com"

# Ids taken by lane B: sorted untested ids [30:60] (n == 91 -> n//3 .. 2n//3).
LANE_B_IDS = (
    "headless_vercel_netlify_detect",
    "heartbeat_frontend",
    "helm_compose_leak",
    "host_platform_detect",
    "hsts_preload_eligibility",
    "hsts_preload_mismatch",
    "html_api_csp_nonce",
    "interactivity_api_directive_xss",
    "jwt_auth_plugin_audit",
    "lead_gen_list_id_enum",
    "magecart_skimmer_patterns",
    "multisite_sso_key_reuse",
    "nft_mint_pubapi",
    "oauth_redirect_misconfig",
    "object_cache_dropin",
    "open_registration",
    "package_lock_audit",
    "perf_of_target",
    "permissions_policy",
    "phpinfo_dangerous_directives",
    "plugin_install_rest_race",
    "postmeta_stored_xss_scan",
    "pwa_service_worker_cache",
    "rest_app_passwords_enum",
    "rest_fields_dos",
    "rest_link_header",
    "rest_namespace_leak",
    "rest_schema_field_leak",
    "rum_beacons",
    "search_highlight_xss",
)


# ---------------------------------------------------------------------------
# scaffolding
# ---------------------------------------------------------------------------
class _Resp:
    """Minimal httpx.Response stand-in (case-insensitive headers, .json())."""

    def __init__(self, status_code=200, text="", *, headers=None, content=None, json_body=None):
        self.status_code = status_code
        if json_body is not None:
            text = json.dumps(json_body)
        self.text = text
        self.content = content if content is not None else text.encode("utf-8")
        if isinstance(headers, httpx.Headers):
            self.headers = headers
        else:
            self.headers = httpx.Headers(headers or {})
        self.url = TARGET

    def json(self):
        return json.loads(self.text)


class _Client:
    """Scripted async client.

    ``routes`` keys are either a path ("/x") or a (METHOD, path) tuple.
    Unrouted requests get ``default`` (404 unless overridden; ``None`` makes
    the client behave like a total network failure).
    """

    def __init__(self, routes=None, default="404"):
        self.base_url = TARGET
        self.routes = routes or {}
        self.default = _Resp(404) if default == "404" else default
        self.calls = []

    def url(self, path):
        if path.startswith("http"):
            return path
        return self.base_url + "/" + path.lstrip("/")

    async def request(self, method, path, **kw):
        self.calls.append((method, path))
        if (method, path) in self.routes:
            return self.routes[(method, path)]
        if path in self.routes:
            return self.routes[path]
        return self.default

    async def get(self, path, **kw):
        return await self.request("GET", path, **kw)

    async def post(self, path, **kw):
        return await self.request("POST", path, **kw)

    async def head(self, path, **kw):
        return await self.request("HEAD", path, **kw)

    async def aclose(self):
        pass


def _ctx(**extra):
    base = {"target": TARGET, "shared": {}, "step": lambda _s: None}
    base.update(extra)
    return base


def _mod(name):
    return importlib.import_module(f"wpsecscan.checks.{name}")


def _run_check(name, client, ctx=None):
    return asyncio.run(_mod(name).check(client, ctx if ctx is not None else _ctx()))


def _html(body="<p>hello</p>", **headers):
    return _Resp(200, f"<html><body>{body}</body></html>", headers=headers)


def _sev(findings):
    return sorted(f.severity for f in findings)


class _ExtState:
    """Controls what the patched httpx.AsyncClient returns."""

    def __init__(self):
        self.raises = True
        self.status = 200
        self.payload = {}
        self.urls = []


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """Sandbox HOME, forbid every real client / resolver, make sleeps free."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")
    monkeypatch.delenv("WPSECSCAN_NO_NETWORK", raising=False)

    import wpsecscan.http as wp_http

    class _NoClient:
        def __init__(self, *a, **k):
            raise AssertionError("check tried to build a real wpsecscan.http.Client")

    monkeypatch.setattr(wp_http, "Client", _NoClient)

    class _NoSyncClient:
        def __init__(self, *a, **k):
            raise AssertionError("check tried to build a real httpx.Client")

    monkeypatch.setattr(httpx, "Client", _NoSyncClient)

    state = _ExtState()

    class _ExtResp:
        def __init__(self, status, payload):
            self.status_code = status
            self._payload = payload

        def json(self):
            return self._payload

    class _FakeAsyncClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, **kw):
            state.urls.append(url)
            if state.raises:
                raise httpx.ConnectError("blocked by test")
            return _ExtResp(state.status, state.payload)

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)

    def _blocked(*a, **k):
        raise OSError("network blocked by test")

    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)

    async def _nosleep(*a, **k):
        return None

    monkeypatch.setattr(asyncio, "sleep", _nosleep)

    real_which = shutil.which
    monkeypatch.setattr(
        shutil, "which", lambda cmd, *a, **k: None if cmd == "lighthouse" else real_which(cmd, *a, **k)
    )
    return state


@pytest.fixture
def ext(_offline):
    """Handle on the patched httpx.AsyncClient (set .raises/.status/.payload)."""
    return _offline


# ---------------------------------------------------------------------------
# (a) every check: registered passive, never raises, returns a list
# ---------------------------------------------------------------------------
_REG = {cid: (name, fn, aggr) for cid, name, fn, aggr in ALL_CHECKS}

_SCENARIOS = {
    "network_failure": lambda: _Client(default=None),
    "all_404": lambda: _Client(),
    "benign_home": lambda: _Client({"/": _html()}),
    "soft_200_everywhere": lambda: _Client(default=_html()),
    "empty_200_everywhere": lambda: _Client(default=_Resp(200, "")),
    "server_error_everywhere": lambda: _Client(default=_Resp(500, "boom")),
}


def test_lane_b_has_30_distinct_ids():
    assert len(LANE_B_IDS) == 30
    assert len(set(LANE_B_IDS)) == 30
    assert list(LANE_B_IDS) == sorted(LANE_B_IDS)


@pytest.mark.parametrize("cid", LANE_B_IDS)
def test_registered_passive_and_module_matches(cid):
    assert cid in _REG, f"{cid} is not registered"
    _name, fn, aggressive = _REG[cid]
    assert aggressive is False
    assert fn.__module__ == f"wpsecscan.checks.{cid}"
    assert inspect.iscoroutinefunction(fn)


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
@pytest.mark.parametrize("cid", LANE_B_IDS)
def test_check_returns_list_on_benign_and_failing_responses(cid, scenario):
    findings = _run_check(cid, _SCENARIOS[scenario]())
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)


# ---------------------------------------------------------------------------
# headless_vercel_netlify_detect
# ---------------------------------------------------------------------------
def test_headless_flags_vercel_with_open_rest():
    c = _Client({"/": _html(**{"x-vercel-id": "iad1::abc"}), "/wp-json/": _Resp(200, "{}")})
    out = _run_check("headless_vercel_netlify_detect", c)
    assert len(out) == 1
    assert out[0].severity == "medium"
    assert out[0].extra == {"platform": "Vercel"}


def test_headless_netlify_via_server_header():
    c = _Client({"/": _html(server="Netlify"), "/wp-json/": _Resp(200, "{}")})
    out = _run_check("headless_vercel_netlify_detect", c)
    assert [f.extra["platform"] for f in out] == ["Netlify"]


def test_headless_silent_without_platform_or_rest():
    assert _run_check("headless_vercel_netlify_detect", _Client({"/": _html(), "/wp-json/": _Resp(200, "{}")})) == []
    c = _Client({"/": _html(**{"x-vercel-id": "iad1::abc"})})  # /wp-json/ -> 404
    assert _run_check("headless_vercel_netlify_detect", c) == []


# ---------------------------------------------------------------------------
# heartbeat_frontend
# ---------------------------------------------------------------------------
def test_heartbeat_loaded_is_low():
    page = _html('<script src="/wp-includes/js/heartbeat.min.js?ver=6.5" id="wp-heartbeat-js"></script>')
    out = _run_check("heartbeat_frontend", _Client({"/": page}))
    assert _sev(out) == ["low"]


def test_heartbeat_absent_is_info_good():
    out = _run_check("heartbeat_frontend", _Client({"/": _html()}))
    assert _sev(out) == ["info"]
    assert "good" in out[0].title


# ---------------------------------------------------------------------------
# helm_compose_leak
# ---------------------------------------------------------------------------
_COMPOSE = (
    "version: '3'\nservices:\n  wp:\n    image: wordpress:6\n    environment:\n"
    "      AWS_KEY: AKIAIOSFODNN7EXAMPLE\n"
)


def test_helm_compose_exposed_with_aws_key():
    out = _run_check("helm_compose_leak", _Client({"/docker-compose.yml": _Resp(200, _COMPOSE)}))
    assert _sev(out) == ["critical", "medium"]
    crit = next(f for f in out if f.severity == "critical")
    assert crit.extra == {"secret_type": "AWS access key"}
    med = next(f for f in out if f.severity == "medium")
    assert med.title == "docker-compose file exposed at /docker-compose.yml"


def test_helm_compose_plain_yaml_has_no_secret_finding():
    body = "replicaCount: 2\nimage:\n  repository: wordpress\n  tag: latest\n"
    out = _run_check("helm_compose_leak", _Client({"/values.yaml": _Resp(200, body)}))
    assert _sev(out) == ["medium"]
    assert "yaml-config" in out[0].title


def test_helm_compose_ignores_html_and_short_bodies():
    html = "<!DOCTYPE html><html><body>services: nope</body></html>"
    assert _run_check("helm_compose_leak", _Client(default=_Resp(200, html))) == []
    assert _run_check("helm_compose_leak", _Client(default=_Resp(200, "a: b"))) == []


# ---------------------------------------------------------------------------
# host_platform_detect
# ---------------------------------------------------------------------------
def test_host_platform_kinsta_header_gives_info_and_advisory():
    out = _run_check("host_platform_detect", _Client({"/": _html(server="kinsta")}))
    assert _sev(out) == ["info", "medium"]
    assert all(f.extra["platform"] == "Kinsta" for f in out)


def test_host_platform_pantheon_header_presence_is_enough():
    out = _run_check("host_platform_detect", _Client({"/": _html(**{"x-pantheon-styx-hostname": "styx1"})}))
    assert {f.extra["platform"] for f in out} == {"Pantheon"}


def test_host_platform_roots_sage_has_no_advisory():
    out = _run_check("host_platform_detect", _Client({"/": _html('<link href="/app/themes/sage/app.css">')}))
    assert [(f.severity, f.extra["platform"]) for f in out] == [("info", "Roots Sage")]


def test_host_platform_bedrock_login_probe():
    c = _Client({"/": _html(), "/wp/wp-login.php": _Resp(200, "<title>WordPress login</title>")})
    out = _run_check("host_platform_detect", c)
    assert [f.extra["platform"] for f in out] == ["Bedrock (Roots)"]


def test_host_platform_vanilla_site_is_silent():
    assert _run_check("host_platform_detect", _Client({"/": _html()})) == []


# ---------------------------------------------------------------------------
# hsts_preload_eligibility
# ---------------------------------------------------------------------------
_GOOD_HSTS = "max-age=63072000; includeSubDomains; preload"


def _patch_status(monkeypatch, value):
    async def _fake(_domain):
        return value

    monkeypatch.setattr(_mod("hsts_preload_eligibility"), "_preload_status", _fake)


def test_hsts_eligibility_eligible_but_unsubmitted_is_low(monkeypatch):
    _patch_status(monkeypatch, None)
    c = _Client({"/": _html(**{"Strict-Transport-Security": _GOOD_HSTS})})
    out = _run_check("hsts_preload_eligibility", c)
    assert _sev(out) == ["low"]
    assert "eligible" in out[0].title


def test_hsts_eligibility_already_preloaded_is_info(monkeypatch):
    _patch_status(monkeypatch, "preloaded")
    c = _Client({"/": _html(**{"Strict-Transport-Security": _GOOD_HSTS})})
    out = _run_check("hsts_preload_eligibility", c)
    assert _sev(out) == ["info"]
    assert "is on the Chrome HSTS preload list" in out[0].title


def test_hsts_eligibility_weak_header_lists_missing_conditions(monkeypatch):
    _patch_status(monkeypatch, None)
    c = _Client({"/": _html(**{"Strict-Transport-Security": "max-age=300"})})
    out = _run_check("hsts_preload_eligibility", c)
    assert _sev(out) == ["info"]
    for needle in ("max-age=300", "includeSubDomains", "preload directive"):
        assert needle in out[0].evidence


def test_hsts_eligibility_silent_for_http_target_or_missing_header(monkeypatch):
    _patch_status(monkeypatch, None)
    c = _Client({"/": _html(**{"Strict-Transport-Security": _GOOD_HSTS})})
    assert _run_check("hsts_preload_eligibility", c, _ctx(target="http://example.com")) == []
    assert _run_check("hsts_preload_eligibility", _Client({"/": _html()})) == []


def test_hsts_eligibility_preload_status_helper_offline(ext, monkeypatch):
    mod = _mod("hsts_preload_eligibility")
    # network failure -> None
    assert asyncio.run(mod._preload_status("example.com")) is None
    # stubbed API answers
    ext.raises = False
    ext.payload = {"status": "pending"}
    assert asyncio.run(mod._preload_status("example.com")) == "pending"
    ext.status = 500
    assert asyncio.run(mod._preload_status("example.com")) is None
    # opt-out env short-circuits before any client is built
    ext.status = 200
    ext.urls.clear()
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    assert asyncio.run(mod._preload_status("example.com")) is None
    assert ext.urls == []


# ---------------------------------------------------------------------------
# hsts_preload_mismatch
# ---------------------------------------------------------------------------
def test_hsts_mismatch_claims_preload_but_not_listed(ext):
    ext.raises = False
    ext.payload = {"status": "unknown"}
    c = _Client({"/": _html(**{"strict-transport-security": _GOOD_HSTS})})
    out = _run_check("hsts_preload_mismatch", c)
    assert _sev(out) == ["low"]
    assert out[0].extra["preload_listed"] is False
    assert "claims preload" in out[0].title
    assert ext.urls == ["https://hstspreload.org/api/v2/status?domain=example.com"]


def test_hsts_mismatch_listed_but_header_dropped_preload(ext):
    ext.raises = False
    ext.payload = {"status": "preloaded"}
    c = _Client({"/": _html(**{"strict-transport-security": "max-age=31536000"})})
    out = _run_check("hsts_preload_mismatch", c)
    assert _sev(out) == ["low"]
    assert out[0].extra["preload_listed"] is True
    assert "dropped" in out[0].title


def test_hsts_mismatch_consistent_states_are_silent(ext):
    ext.raises = False
    ext.payload = {"status": "preloaded"}
    claims = _Client({"/": _html(**{"strict-transport-security": _GOOD_HSTS})})
    assert _run_check("hsts_preload_mismatch", claims) == []
    ext.payload = {"status": "unknown"}
    plain = _Client({"/": _html(**{"strict-transport-security": "max-age=31536000"})})
    assert _run_check("hsts_preload_mismatch", plain) == []


def test_hsts_mismatch_api_down_or_non_200_is_silent(ext):
    c = _Client({"/": _html(**{"strict-transport-security": _GOOD_HSTS})})
    assert _run_check("hsts_preload_mismatch", c) == []  # ext.raises is True
    ext.raises = False
    ext.status = 503
    assert _run_check("hsts_preload_mismatch", c) == []


# ---------------------------------------------------------------------------
# html_api_csp_nonce
# ---------------------------------------------------------------------------
_CSP = "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'"


def test_csp_nonce_flags_inline_script_without_nonce():
    page = _html('<script nonce="abc123">a()</script><script>b()</script><script src="/x.js"></script>',
                 **{"content-security-policy": _CSP})
    out = _run_check("html_api_csp_nonce", _Client({"/": page}))
    assert _sev(out) == ["medium"]
    assert out[0].extra == {"inline_with_nonce": 1, "inline_no_nonce": 1}


def test_csp_nonce_silent_when_all_inline_scripts_have_nonce_or_csp_has_none():
    ok = _html('<script nonce="abc123">a()</script>', **{"content-security-policy": _CSP})
    assert _run_check("html_api_csp_nonce", _Client({"/": ok})) == []
    no_nonce_csp = _html("<script>b()</script>", **{"content-security-policy": "default-src 'self'"})
    assert _run_check("html_api_csp_nonce", _Client({"/": no_nonce_csp})) == []


# ---------------------------------------------------------------------------
# interactivity_api_directive_xss
# ---------------------------------------------------------------------------
def test_interactivity_reflected_canary_in_directive_is_high_per_probe():
    page = _html('<div data-wp-bind--title="state.WPSECSCAN_XX_77">x</div>')
    out = _run_check("interactivity_api_directive_xss", _Client(default=page))
    assert _sev(out) == ["high", "high", "high"]  # one per probe path
    assert all(f.title.startswith("F66") for f in out)


def test_interactivity_not_detected_is_info():
    out = _run_check("interactivity_api_directive_xss", _Client(default=_html()))
    assert _sev(out) == ["info"]


def test_interactivity_escaped_directive_is_silent():
    page = _html('<div data-wp-context="{&quot;a&quot;:1}">x</div>')
    assert _run_check("interactivity_api_directive_xss", _Client(default=page)) == []


# ---------------------------------------------------------------------------
# jwt_auth_plugin_audit
# ---------------------------------------------------------------------------
_JWT = "/wp-json/jwt-auth/v1/token"


def test_jwt_secret_missing_is_critical():
    body = '{"code":"jwt_auth_bad_config","message":"JWT is not configurated properly, please contact the admin"}'
    out = _run_check("jwt_auth_plugin_audit", _Client({_JWT: _Resp(403, body)}))
    assert _sev(out) == ["critical"]
    assert out[0].extra == {"category": "jwt-secret-missing"}


def test_jwt_hardened_rejection_is_info():
    out = _run_check("jwt_auth_plugin_audit", _Client({_JWT: _Resp(403, '{"code":"incorrect_password"}')}))
    assert _sev(out) == ["info"]
    assert out[0].extra == {"status": 403}


def test_jwt_missing_endpoint_or_other_status_is_silent():
    assert _run_check("jwt_auth_plugin_audit", _Client()) == []
    assert _run_check("jwt_auth_plugin_audit", _Client({_JWT: _Resp(200, "{}")})) == []


# ---------------------------------------------------------------------------
# lead_gen_list_id_enum
# ---------------------------------------------------------------------------
def test_lead_gen_list_ids_leaked_is_low():
    form = '<input type="hidden" name="list_id" value="abc12345"><div data-audience-id="Zx9Yw8Vv7U"></div>'
    out = _run_check("lead_gen_list_id_enum", _Client({"/": _html(form)}))
    assert _sev(out) == ["low"]
    assert out[0].extra["list_ids"] == ["Zx9Yw8Vv7U", "abc12345"]


def test_lead_gen_no_ids_is_silent():
    assert _run_check("lead_gen_list_id_enum", _Client({"/": _html()})) == []


# ---------------------------------------------------------------------------
# magecart_skimmer_patterns
# ---------------------------------------------------------------------------
def test_magecart_fake_cdn_on_checkout_is_critical():
    body = "<form>Card number <input name='cardnumber'></form><script src='https://jquery-cdn.com/j.js'></script>"
    out = _run_check("magecart_skimmer_patterns", _Client({"/checkout/": _Resp(200, body)}))
    assert _sev(out) == ["critical"]
    hits = out[0].extra["hits"]
    assert {"path": "/checkout/", "pattern": "Magecart Group 7 — fake-jQuery CDN"} in hits


def test_magecart_clean_checkout_or_non_payment_page_is_silent():
    clean = "<form>Card number <input name='x'></form><script src='https://js.stripe.com/v3/'></script>"
    assert _run_check("magecart_skimmer_patterns", _Client({"/checkout/": _Resp(200, clean)})) == []
    # skimmer-looking string but no card/payment context -> skipped by design
    off_topic = "<script src='https://jquery-cdn.com/j.js'></script>"
    assert _run_check("magecart_skimmer_patterns", _Client({"/cart/": _Resp(200, off_topic)})) == []


# ---------------------------------------------------------------------------
# multisite_sso_key_reuse
# ---------------------------------------------------------------------------
def _login_with_cookies(*cookies):
    return _Resp(200, "login", headers=httpx.Headers([("set-cookie", c) for c in cookies]))


def test_multisite_network_wide_cookie_is_medium():
    c = _Client({
        "/": _html('<a href="/wp-admin/network/">Network</a>'),
        "/wp-login.php": _login_with_cookies("wordpress_test_cookie=WP%20Cookie%20check; path=/; secure"),
    })
    out = _run_check("multisite_sso_key_reuse", c)
    assert _sev(out) == ["medium"]
    assert len(out[0].extra["cookies_sample"]) == 1


def test_multisite_detected_via_network_admin_probe():
    c = _Client({
        "/wp-admin/network/": _Resp(302, ""),
        "/wp-login.php": _login_with_cookies("wordpress_logged_in_x=1; Path=/"),
    })
    assert _sev(_run_check("multisite_sso_key_reuse", c)) == ["medium"]


def test_multisite_subpath_cookie_or_single_site_is_silent():
    scoped = _Client({
        "/": _html('<a href="/wp-admin/network/">N</a>'),
        "/wp-login.php": _login_with_cookies("wordpress_test_cookie=1; path=/blog/"),
    })
    assert _run_check("multisite_sso_key_reuse", scoped) == []
    single = _Client({"/": _html(), "/wp-login.php": _login_with_cookies("wordpress_test_cookie=1; path=/")})
    assert _run_check("multisite_sso_key_reuse", single) == []


# ---------------------------------------------------------------------------
# nft_mint_pubapi
# ---------------------------------------------------------------------------
def test_nft_mint_open_endpoint_is_critical():
    c = _Client({"/wp-json/nft/v1/mint": _Resp(200, '{"minted":true}')})
    out = _run_check("nft_mint_pubapi", c)
    assert _sev(out) == ["critical"]
    assert out[0].url.endswith("/wp-json/nft/v1/mint")


def test_nft_mint_400_without_auth_message_is_medium_with_auth_message_silent():
    open_400 = _Client({"/wp-json/web3/v1/mint": _Resp(400, '{"code":"bad_json"}')})
    assert _sev(_run_check("nft_mint_pubapi", open_400)) == ["medium"]
    gated_400 = _Client({"/wp-json/web3/v1/mint": _Resp(400, '{"message":"login required"}')})
    assert _run_check("nft_mint_pubapi", gated_400) == []


def test_nft_mint_auth_gated_or_absent_is_silent():
    assert _run_check("nft_mint_pubapi", _Client(default=_Resp(401, "{}"))) == []
    assert _run_check("nft_mint_pubapi", _Client()) == []


# ---------------------------------------------------------------------------
# oauth_redirect_misconfig
# ---------------------------------------------------------------------------
def _google_link(redirect):
    return (
        '<a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=1234567890abcdef.apps'
        f'&amp;redirect_uri={redirect}&amp;response_type=code">Sign in</a>'
    )


def test_oauth_localhost_redirect_is_medium():
    page = _html(_google_link("http%3A%2F%2Flocalhost%3A3000%2Fcb"))
    out = _run_check("oauth_redirect_misconfig", _Client({"/": page}))
    assert _sev(out) == ["medium"]
    assert out[0].title.startswith("Google OAuth redirect_uri")
    assert "localhost" in out[0].evidence


def test_oauth_facebook_staging_redirect_is_medium():
    link = ('<a href="https://www.facebook.com/v12.0/dialog/oauth?client_id=99'
            '&redirect_uri=https://staging.example.com/cb">fb</a>')
    out = _run_check("oauth_redirect_misconfig", _Client({"/": _html(link)}))
    assert [f.title.split()[0] for f in out] == ["Facebook"]


def test_oauth_production_redirect_or_no_oauth_is_silent():
    prod = _html(_google_link("https%3A%2F%2Fexample.com%2Fcb"))
    assert _run_check("oauth_redirect_misconfig", _Client({"/": prod})) == []
    assert _run_check("oauth_redirect_misconfig", _Client({"/": _html()})) == []


# ---------------------------------------------------------------------------
# object_cache_dropin
# ---------------------------------------------------------------------------
_OC = "/wp-content/object-cache.php"


def test_object_cache_source_exposed_is_high_and_fingerprinted():
    body = "<?php\n/** @package Redis_Object_Cache */\nclass WP_Object_Cache {}"
    out = _run_check("object_cache_dropin", _Client({_OC: _Resp(200, body)}))
    assert _sev(out) == ["high"]
    assert out[0].extra == {"vendor": "Redis Object Cache"}


def test_object_cache_unidentified_vendor():
    out = _run_check("object_cache_dropin", _Client({_OC: _Resp(200, "<?php // custom")}))
    assert out[0].extra == {"vendor": "unidentified vendor"}


def test_object_cache_soft_404_or_missing_is_silent():
    assert _run_check("object_cache_dropin", _Client({_OC: _html()})) == []
    assert _run_check("object_cache_dropin", _Client()) == []


# ---------------------------------------------------------------------------
# open_registration
# ---------------------------------------------------------------------------
_REG_PAGE = '<form action="register"><input name="user_login"></form>'
_REG_URL = "/wp-login.php?action=register"


def test_open_registration_without_membership_plugin_is_medium():
    out = _run_check("open_registration", _Client({_REG_URL: _html(_REG_PAGE)}))
    assert _sev(out) == ["medium"]


def test_open_registration_with_membership_plugin_is_info():
    ctx = _ctx(shared={"plugins": {"memberpress": {"version": "1.0"}}})
    out = _run_check("open_registration", _Client({_REG_URL: _html(_REG_PAGE)}), ctx)
    assert _sev(out) == ["info"]


def test_open_registration_closed_or_not_a_form_is_silent():
    assert _run_check("open_registration", _Client()) == []
    assert _run_check("open_registration", _Client({_REG_URL: _html("<p>Registration disabled</p>")})) == []


# ---------------------------------------------------------------------------
# package_lock_audit
# ---------------------------------------------------------------------------
def test_package_lock_exposed_with_vulnerable_lodash():
    body = json.dumps({"name": "theme", "dependencies": {"lodash": {"version": "4.17.15"}}})
    out = _run_check("package_lock_audit", _Client({"/package-lock.json": _Resp(200, body)}))
    assert _sev(out) == ["high", "medium"]
    vuln = next(f for f in out if f.severity == "high")
    assert vuln.extra["package"] == "lodash" and vuln.extra["version"] == "4.17.15"


def test_package_json_exposed_is_low_and_patched_dep_not_flagged():
    body = json.dumps({"name": "theme", "dependencies": {"lodash": "4.17.21"}})
    out = _run_check("package_lock_audit", _Client({"/package.json": _Resp(200, body)}))
    assert _sev(out) == ["low"]


def test_package_lock_registry_token_is_high():
    body = '{"name": "x", "resolved": "https://registry.npmjs.org/p/-/p-1.tgz?token=abcdefghijklmnopqrstuvwx"}'
    out = _run_check("package_lock_audit", _Client({"/package-lock.json": _Resp(200, body)}))
    assert "npm registry auth token leaked in resolved URL" in [f.title for f in out]


def test_package_lock_soft_404_html_is_silent():
    assert _run_check("package_lock_audit", _Client(default=_html())) == []


def test_package_lock_version_le_helper():
    mod = _mod("package_lock_audit")
    assert mod._version_le("4.17.20", "4.17.20") is True
    assert mod._version_le("^4.17.15", "4.17.20") is True
    assert mod._version_le("4.17.21", "4.17.20") is False


# ---------------------------------------------------------------------------
# perf_of_target
# ---------------------------------------------------------------------------
def test_perf_benign_site_reports_ttfb_and_spread_as_info():
    out = _run_check("perf_of_target", _Client({"/": _html()}))
    titles = [f.title for f in out]
    assert any(t.startswith("P146") for t in titles)
    assert any(t.startswith("P150") for t in titles)
    assert not any(t.startswith("P149") for t in titles)  # no cache headers
    assert set(_sev(out)) == {"info"}


def test_perf_cache_misses_are_medium_and_hits_are_info():
    miss = _Client({"/": _html(**{"cf-cache-status": "MISS"})})
    p149 = [f for f in _run_check("perf_of_target", miss) if f.title.startswith("P149")]
    assert [(f.severity, f.extra["cache_hit_ratio"]) for f in p149] == [("medium", 0.0)]
    hit = _Client({"/": _html(**{"x-cache": "HIT from cdn"})})
    p149 = [f for f in _run_check("perf_of_target", hit) if f.title.startswith("P149")]
    assert [(f.severity, f.extra["cache_hit_ratio"]) for f in p149] == [("info", 1.0)]


def test_perf_companion_query_budget_uses_patched_client_only(ext):
    ext.raises = False
    ext.payload = {"queries": 80}
    out = _run_check("perf_of_target", _Client({"/": _html()}), _ctx(companion_token="tok"))
    p148 = [f for f in out if f.title.startswith("P148")]
    assert [(f.severity, f.extra["db_queries"]) for f in p148] == [("medium", 80)]
    assert ext.urls == ["https://example.com/wp-json/wpsecscan/v1/diagnostics"]


def test_perf_without_token_makes_no_external_request(ext):
    _run_check("perf_of_target", _Client({"/": _html()}))
    assert ext.urls == []


def test_perf_total_failure_returns_empty_list():
    assert _run_check("perf_of_target", _Client(default=None)) == []


# ---------------------------------------------------------------------------
# permissions_policy
# ---------------------------------------------------------------------------
def test_permissions_policy_missing_is_low():
    out = _run_check("permissions_policy", _Client({"/": _html()}))
    assert _sev(out) == ["low"]
    assert out[0].title == "Permissions-Policy header missing"


def test_permissions_policy_wildcard_grant_is_medium_plus_floc_low():
    c = _Client({"/": _html(**{"Permissions-Policy": "camera=*, microphone=()"})})
    out = _run_check("permissions_policy", c)
    assert _sev(out) == ["low", "medium"]
    assert "camera" in next(f for f in out if f.severity == "medium").evidence


def test_permissions_policy_deny_by_default_is_info_reasonable():
    c = _Client({"/": _html(**{"permissions-policy": "camera=(), microphone=(self), interest-cohort=()"})})
    out = _run_check("permissions_policy", c)
    assert _sev(out) == ["info"]
    assert "looks reasonable" in out[0].title


def test_permissions_policy_parse_helper():
    mod = _mod("permissions_policy")
    assert mod._parse_policy("") == {}
    assert mod._parse_policy("Camera=(), geolocation=(self)") == {"camera": "()", "geolocation": "(self)"}


# ---------------------------------------------------------------------------
# phpinfo_dangerous_directives
# ---------------------------------------------------------------------------
def _phpinfo(**directives):
    rows = "".join(
        f'<tr><td class="e">{k}</td><td class="v">{v}</td><td class="v">{v}</td></tr>'
        for k, v in directives.items()
    )
    return f"<html><title>phpinfo()</title><body><table>{rows}</table></body></html>"


def test_phpinfo_dangerous_directives_flagged_by_severity():
    page = _phpinfo(allow_url_include="On", display_errors="On", allow_url_fopen="Off")
    out = _run_check("phpinfo_dangerous_directives", _Client({"/phpinfo.php": _Resp(200, page)}))
    assert _sev(out) == ["critical", "medium"]
    assert {f.extra["directive"] for f in out} == {"allow_url_include", "display_errors"}


def test_phpinfo_safe_values_or_no_phpinfo_are_silent():
    safe = _phpinfo(allow_url_include="Off", display_errors="Off", expose_php="Off")
    assert _run_check("phpinfo_dangerous_directives", _Client({"/info.php": _Resp(200, safe)})) == []
    assert _run_check("phpinfo_dangerous_directives", _Client()) == []


# ---------------------------------------------------------------------------
# plugin_install_rest_race
# ---------------------------------------------------------------------------
_PLUGINS = "/wp-json/wp/v2/plugins"


def test_plugin_install_unauthenticated_success_is_critical():
    out = _run_check("plugin_install_rest_race", _Client({_PLUGINS: _Resp(201, '{"status":"inactive"}')}))
    assert _sev(out) == ["critical"]
    assert out[0].extra == {"status": 201}


def test_plugin_install_auth_gated_is_info():
    out = _run_check("plugin_install_rest_race", _Client({_PLUGINS: _Resp(401, "{}")}))
    assert _sev(out) == ["info"]


def test_plugin_install_other_statuses_are_silent():
    assert _run_check("plugin_install_rest_race", _Client()) == []
    assert _run_check("plugin_install_rest_race", _Client({_PLUGINS: _Resp(500, "")})) == []


# ---------------------------------------------------------------------------
# postmeta_stored_xss_scan
# ---------------------------------------------------------------------------
_POSTS_URL = "/wp-json/wp/v2/posts?per_page=30&_fields=id,link,meta"


def test_postmeta_xss_payload_in_meta_is_critical():
    posts = [{"id": 7, "link": TARGET + "/a/", "meta": {"note": "<script>alert(1)</script>", "n": 3}}]
    out = _run_check("postmeta_stored_xss_scan", _Client({_POSTS_URL: _Resp(200, json_body=posts)}))
    assert _sev(out) == ["critical"]
    assert out[0].extra["matches"][0]["post_id"] == 7
    assert out[0].extra["matches"][0]["meta_key"] == "note"


def test_postmeta_clean_meta_or_odd_shapes_are_silent():
    clean = [{"id": 1, "link": "x", "meta": {"note": "plain text", "n": 1}}, {"id": 2, "meta": []}]
    assert _run_check("postmeta_stored_xss_scan", _Client({_POSTS_URL: _Resp(200, json_body=clean)})) == []
    assert _run_check("postmeta_stored_xss_scan", _Client({_POSTS_URL: _Resp(200, "not json")})) == []
    assert _run_check("postmeta_stored_xss_scan", _Client({_POSTS_URL: _Resp(200, json_body={"a": 1})})) == []
    assert _run_check("postmeta_stored_xss_scan", _Client()) == []


# ---------------------------------------------------------------------------
# pwa_service_worker_cache
# ---------------------------------------------------------------------------
def test_pwa_sw_precaching_admin_urls_is_high():
    sw = 'precacheAndRoute(["/wp-admin/admin-ajax.php", "/index.php", \'/wp-admin/profile.php\'])'
    out = _run_check("pwa_service_worker_cache", _Client({"/sw.js": _Resp(200, sw)}))
    assert _sev(out) == ["high"]
    assert out[0].extra["admin_urls_sample"] == ["/wp-admin/admin-ajax.php", "/wp-admin/profile.php"]


def test_pwa_sw_without_admin_paths_or_missing_is_silent():
    assert _run_check("pwa_service_worker_cache", _Client({"/sw.js": _Resp(200, 'cache.add("/index.php")')})) == []
    assert _run_check("pwa_service_worker_cache", _Client()) == []


# ---------------------------------------------------------------------------
# rest_app_passwords_enum
# ---------------------------------------------------------------------------
_APP_ME = "/wp-json/wp/v2/users/me/application-passwords"


def test_app_passwords_open_endpoint_is_high():
    out = _run_check("rest_app_passwords_enum", _Client({_APP_ME: _Resp(200, "[]")}))
    assert _sev(out) == ["high"]
    assert out[0].url.endswith("/application-passwords")


def test_app_passwords_401_is_a_single_info_on_first_path_only():
    out = _run_check("rest_app_passwords_enum", _Client(default=_Resp(401, "{}")))
    assert _sev(out) == ["info"]


def test_app_passwords_404_is_silent():
    assert _run_check("rest_app_passwords_enum", _Client()) == []


# ---------------------------------------------------------------------------
# rest_fields_dos
# ---------------------------------------------------------------------------
_FIELDS = "/wp-json/?_fields=*"


def test_rest_fields_large_response_is_medium():
    big = _Resp(200, "", content=b"x" * (600 * 1024))
    out = _run_check("rest_fields_dos", _Client({_FIELDS: big}))
    assert _sev(out) == ["medium"]
    assert out[0].extra == {"response_bytes": 600 * 1024}


def test_rest_fields_small_response_is_info_and_failure_is_silent():
    small = _Resp(200, "", content=b"x" * 2048)
    assert _sev(_run_check("rest_fields_dos", _Client({_FIELDS: small}))) == ["info"]
    assert _run_check("rest_fields_dos", _Client()) == []


# ---------------------------------------------------------------------------
# rest_link_header
# ---------------------------------------------------------------------------
def test_rest_link_header_internal_host_is_medium():
    link = '<https://staging.corp.internal/wp-json/>; rel="https://api.w.org/"'
    out = _run_check("rest_link_header", _Client({"/": _html(Link=link)}))
    assert _sev(out) == ["medium"]
    assert "1 internal-looking URL" in out[0].title


def test_rest_link_header_same_host_other_host_or_absent_is_silent():
    same = '<https://example.com/wp-json/>; rel="https://api.w.org/"'
    assert _run_check("rest_link_header", _Client({"/": _html(Link=same)})) == []
    cdn = '<https://cdn.example.net/wp-json/>; rel="https://api.w.org/"'
    assert _run_check("rest_link_header", _Client({"/": _html(Link=cdn)})) == []
    assert _run_check("rest_link_header", _Client({"/": _html()})) == []


# ---------------------------------------------------------------------------
# rest_namespace_leak
# ---------------------------------------------------------------------------
def test_rest_namespace_staging_token_is_low():
    root = {"namespaces": ["oembed/1.0", "wp/v2", "myplugin-staging/v1"]}
    out = _run_check("rest_namespace_leak", _Client({"/wp-json/": _Resp(200, json_body=root)}))
    assert _sev(out) == ["low"]
    assert out[0].extra == {"suspect_namespaces": ["myplugin-staging/v1"]}


def test_rest_namespace_clean_or_malformed_is_silent():
    clean = {"namespaces": ["oembed/1.0", "wp/v2"]}
    assert _run_check("rest_namespace_leak", _Client({"/wp-json/": _Resp(200, json_body=clean)})) == []
    assert _run_check("rest_namespace_leak", _Client({"/wp-json/": _Resp(200, "<html>")})) == []
    assert _run_check("rest_namespace_leak", _Client({"/wp-json/": _Resp(200, json_body=["a"])})) == []
    assert _run_check("rest_namespace_leak", _Client()) == []


# ---------------------------------------------------------------------------
# rest_schema_field_leak
# ---------------------------------------------------------------------------
def test_rest_schema_internal_field_is_medium_for_that_path_only():
    schema = json.dumps({"schema": {"properties": {"internal_notes": {}, "title": {}}}})
    c = _Client({("OPTIONS", "/wp-json/wp/v2/posts"): _Resp(200, schema)})
    out = _run_check("rest_schema_field_leak", c)
    assert _sev(out) == ["medium"]
    assert out[0].title.endswith("/wp-json/wp/v2/posts")
    assert any("internal_notes" in s for s in out[0].extra["suspicious_fields"])
    assert {m for m, _p in c.calls} == {"OPTIONS"}


def test_rest_schema_innocuous_fields_are_silent():
    schema = json.dumps({"schema": {"properties": {"title": {}, "content": {}}}})
    assert _run_check("rest_schema_field_leak", _Client(default=_Resp(200, schema))) == []


# ---------------------------------------------------------------------------
# rum_beacons
# ---------------------------------------------------------------------------
def test_rum_beacons_detected_is_low_with_vendor_list():
    page = _html("<script>window.NREUM={};</script><script src='https://static.cloudflareinsights.com/b.js'></script>")
    out = _run_check("rum_beacons", _Client({"/": page}))
    assert _sev(out) == ["low"]
    assert out[0].extra["rum_vendors"] == ["New Relic Browser", "Cloudflare RUM"]


def test_rum_beacons_absent_is_silent():
    assert _run_check("rum_beacons", _Client({"/": _html()})) == []


# ---------------------------------------------------------------------------
# search_highlight_xss
# ---------------------------------------------------------------------------
def test_search_highlight_unescaped_payload_is_high():
    page = _html("<mark><svg/onload=wpsecscanXSSprobe></mark>")
    out = _run_check("search_highlight_xss", _Client({"/": page}))
    assert _sev(out) == ["high"]
    assert out[0].extra == {"category": "reflected-xss"}


def test_search_highlight_escaped_payload_or_no_reflection_is_silent():
    escaped = _html("<mark>&lt;svg/onload=wpsecscanXSSprobe&gt;</mark>")
    assert _run_check("search_highlight_xss", _Client({"/": escaped})) == []
    assert _run_check("search_highlight_xss", _Client({"/": _html()})) == []
