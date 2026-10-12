"""v2.9.1 W11 (lane a) -- offline crash/logic tests for registered checks that had
ZERO test references.

Slice: the FIRST THIRD (sorted ascending, indices 0..30) of the 95 registered check
ids that no other test file referenced on 2026-10-12.  Lanes b/c take indices 31..61
and 62..94 of the same sorted list.

Everything is offline:
  * a scripted FakeClient stands in for ``wpsecscan.http.Client``;
  * ``httpx.AsyncClient`` / ``httpx.Client`` are replaced with real httpx clients bound
    to an ``httpx.MockTransport`` (so checks that build their own client never leave
    the process);
  * ``socket.create_connection`` / ``getaddrinfo`` raise;
  * HOME / USERPROFILE point at ``tmp_path`` and ``WPSECSCAN_NO_LIVE=1``.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import socket
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from wpsecscan.checks import ALL_CHECKS
from wpsecscan.models import Finding

# --------------------------------------------------------------------------
# The slice (sorted untested ids, indices 0..30)
# --------------------------------------------------------------------------
SLICE_A = (
    "a11y_wcag_aaa",
    "admin_invite_link_scan",
    "ai_agent_webhook_leak",
    "ai_chatbot_endpoint_leak",
    "ai_plugin_prompt_storage",
    "algolia_elastic_frontend_keys",
    "amp_transitional_redirect",
    "app_passwords_stale_audit",
    "block_bindings_exposure",
    "block_style_variations_url",
    "bucket_shadow_takeover",
    "companion_v13",
    "companion_v14",
    "composer_npm_typosquat",
    "cookie_banner_cosmetic_vs_blocking",
    "cookie_consent_desync",
    "core_checksums",
    "crypto_payment_callback_audit",
    "csp_report_endpoint",
    "ct_log_recent_certs",
    "ct_log_shadow_cert",
    "db_trigger_audit",
    "debug_log_pii_sniff",
    "email_obfuscation_audit",
    "font_library_api_ssrf",
    "form_builder_upload_bypass",
    "gdpr_dsr_endpoint_enum",
    "github_actions_workflow_leak",
    "gtm_inventory",
    "headless_cors_lockdown",
    "headless_vercel_netlify_detect",
)

_FNS = {cid: fn for cid, _name, fn, _agg in ALL_CHECKS}
_AGGRESSIVE = {cid: agg for cid, _name, _fn, agg in ALL_CHECKS}


def _mod(name: str):
    # NOTE: wpsecscan.checks re-exports each check function under its module's name,
    # so ``import wpsecscan.checks.x as m`` would hand back the function.
    return importlib.import_module(f"wpsecscan.checks.{name}")


_REAL_ASYNC_CLIENT = httpx.AsyncClient
_REAL_SYNC_CLIENT = httpx.Client
_REAL_FETCH_CHECKSUMS = _mod("core_checksums")._fetch_checksums
_REAL_LIVE_ISSUER = _mod("ct_log_shadow_cert")._live_cert_issuer


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------
class Resp:
    def __init__(self, status: int = 200, text: str = "", headers=None, *, json_body=None,
                 content: bytes | None = None) -> None:
        self.status_code = status
        self.text = json.dumps(json_body) if json_body is not None else text
        if content is not None and not self.text:
            self.text = content.decode("utf-8", errors="replace")
        self.content = content if content is not None else self.text.encode("utf-8")
        self.headers = httpx.Headers(headers or {})
        self.url = ""

    def json(self):
        return json.loads(self.text)


_UNSET = object()


class FakeClient:
    """Scripted async stand-in for wpsecscan.http.Client.

    routes: {(METHOD, path) or path: Resp | callable(method, path, kwargs) -> Resp | None}
    default: Resp(404) unless overridden (None and callables allowed).
    """

    def __init__(self, routes=None, *, default=_UNSET, base_url: str = "https://example.com") -> None:
        self.routes = routes or {}
        self.default = Resp(404) if default is _UNSET else default
        self.base_url = base_url
        self.calls: list[tuple[str, str]] = []
        self.kwargs: list[dict] = []

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return self.base_url.rstrip("/") + "/" + path.lstrip("/")

    async def request(self, method: str, path: str, **kw):
        self.calls.append((method, path))
        self.kwargs.append(kw)
        hit = self.routes.get((method, path), self.routes.get(path, _UNSET))
        if hit is _UNSET:
            hit = self.default
        return hit(method, path, kw) if callable(hit) else hit

    async def get(self, path: str, **kw):
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw):
        return await self.request("POST", path, **kw)

    async def head(self, path: str, **kw):
        return await self.request("HEAD", path, **kw)


class _RaisingClient(FakeClient):
    async def request(self, method: str, path: str, **kw):
        self.calls.append((method, path))
        raise RuntimeError("boom")


class _Net:
    """Handler slot behind the patched httpx clients. Default: 404 for everything."""

    def __init__(self) -> None:
        self.handler = None
        self.seen: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if self.handler is None:
            return httpx.Response(404, text="not found")
        return self.handler(request)


@pytest.fixture(autouse=True)
def net(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")
    monkeypatch.delenv("WPSECSCAN_NO_NETWORK", raising=False)

    n = _Net()

    def _async_factory(*_a, **kw):
        kw.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(n), **kw)

    def _sync_factory(*_a, **kw):
        kw.pop("transport", None)
        return _REAL_SYNC_CLIENT(transport=httpx.MockTransport(n), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _async_factory)
    monkeypatch.setattr(httpx, "Client", _sync_factory)

    def _blocked(*_a, **_k):
        raise OSError("network blocked by test")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)

    import wpsecscan.http as _wh

    class _NoClient:
        def __init__(self, *a, **k) -> None:
            raise AssertionError("a check built a real wpsecscan.http.Client in a test")

    monkeypatch.setattr(_wh, "Client", _NoClient)

    async def _no_checksums(_version):
        return None

    async def _no_issuer(_host):
        return ""

    monkeypatch.setattr(_mod("core_checksums"), "_fetch_checksums", _no_checksums)
    monkeypatch.setattr(_mod("ct_log_shadow_cert"), "_live_cert_issuer", _no_issuer)
    return n


def _ctx(**extra) -> dict:
    base = {"target": "https://example.com", "shared": {}, "step": lambda _s: None, "aggressive": False}
    base.update(extra)
    return base


def _run(cid: str, client, ctx: dict | None = None):
    return asyncio.run(_FNS[cid](client, ctx if ctx is not None else _ctx()))


def _sevs(findings) -> list[str]:
    return [f.severity for f in findings]


def _only(findings) -> Finding:
    assert len(findings) == 1, [(f.severity, f.title) for f in findings]
    return findings[0]


# Per-check ctx additions so the smoke runs get PAST the early "not configured" exits.
_SMOKE_CTX = {
    "companion_v13": {"companion_token": "tok"},
    "companion_v14": {"companion_token": "tok"},
    "app_passwords_stale_audit": {"auth_cookies": {"wordpress_logged_in": "x"}},
    "core_checksums": {"shared": {"wp_version": "6.5.2"}},
}

_HTML = "<html><head><title>Hi</title></head><body><h1>Hello</h1></body></html>"
_SMOKE_RESPONSES = {
    "404": lambda: Resp(404, "not found"),
    "200-empty": lambda: Resp(200, ""),
    "200-html": lambda: Resp(200, _HTML, {"content-type": "text/html"}),
    "200-json-list": lambda: Resp(200, json_body=[]),
    "200-json-obj": lambda: Resp(200, json_body={}),
    "500": lambda: Resp(500, "oops"),
    "none": lambda: None,
}


# --------------------------------------------------------------------------
# Registry / smoke (crash-class guard for the whole slice)
# --------------------------------------------------------------------------
def test_slice_is_sorted_registered_and_passive():
    assert list(SLICE_A) == sorted(SLICE_A)
    assert len(SLICE_A) == len(set(SLICE_A)) == 31
    for cid in SLICE_A:
        assert cid in _FNS, cid
        assert _AGGRESSIVE[cid] is False, f"{cid} is aggressive; this lane only covers passive checks"


@pytest.mark.parametrize("profile", sorted(_SMOKE_RESPONSES))
@pytest.mark.parametrize("cid", SLICE_A)
def test_smoke_runs_without_raising(cid, profile):
    """Every check survives every canned benign response and returns a list of Findings."""
    make = _SMOKE_RESPONSES[profile]
    client = FakeClient(default=make())
    ctx = _ctx(**_SMOKE_CTX.get(cid, {}))
    out = _run(cid, client, ctx)
    assert isinstance(out, list)
    assert all(isinstance(f, Finding) for f in out)


@pytest.mark.parametrize("cid", SLICE_A)
def test_smoke_survives_a_client_that_raises_is_documented(cid):
    """Checks may let a hard client exception propagate (the runner wraps them) but must
    not hang or touch the network.  We only assert it terminates with a list OR the
    client's own RuntimeError -- never a NameError/TypeError/AttributeError."""
    client = _RaisingClient()
    ctx = _ctx(**_SMOKE_CTX.get(cid, {}))
    try:
        out = _run(cid, client, ctx)
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:
        assert isinstance(out, list)


def test_network_guard_canaries(net):
    with pytest.raises(OSError):
        socket.create_connection(("example.com", 443))
    # The real TLS-issuer probe degrades to "" when the socket is blocked.
    assert asyncio.run(_REAL_LIVE_ISSUER("example.com")) == ""

    async def _go():
        async with httpx.AsyncClient() as c:
            return (await c.get("https://example.com/x")).status_code

    assert asyncio.run(_go()) == 404
    assert [r.url.host for r in net.seen] == ["example.com"]


# --------------------------------------------------------------------------
# a11y_wcag_aaa
# --------------------------------------------------------------------------
def test_a11y_aaa_no_h1_is_low():
    out = _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, "<html><body><p>x</p></body></html>")}))
    f = _only(out)
    assert f.severity == "low" and "2.4.10" in f.title


def test_a11y_aaa_multiple_h1_is_info_and_single_h1_is_clean():
    two = _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, "<h1>a</h1><h1>b</h1>")}))
    assert _sevs(two) == ["info"] and "Multiple <h1>" in two[0].title
    assert _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, "<h1>a</h1><p>fine</p>")})) == []


def test_a11y_aaa_autoplay_video_without_controls():
    bad = _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, "<h1>t</h1><video src=a.mp4 autoplay></video>")}))
    assert _sevs(bad) == ["medium"] and "2.3.2" in bad[0].title
    ok = _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, "<h1>t</h1><video controls autoplay></video>")}))
    assert ok == []


def test_a11y_aaa_reading_level_only_fires_on_long_dense_text():
    dense = "<h1>t</h1><p>" + ("institutionalization " * 250) + ".</p>"
    out = _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, dense)}))
    assert _sevs(out) == ["info"] and "3.1.5" in out[0].title
    simple = "<h1>t</h1><p>" + ("See the cat. " * 120) + "</p>"
    assert _run("a11y_wcag_aaa", FakeClient({"/": Resp(200, simple)})) == []


def test_a11y_aaa_non_200_and_helpers():
    assert _run("a11y_wcag_aaa", FakeClient({"/": Resp(503, "<p>down</p>")})) == []
    m = _mod("a11y_wcag_aaa")
    assert m._flesch_kincaid_grade("") == 0.0
    assert m._sentence_count("no punctuation") == 1
    assert m._word_count("one two three") == 3


# --------------------------------------------------------------------------
# admin_invite_link_scan
# --------------------------------------------------------------------------
def test_admin_invite_links_flagged_across_pages():
    client = FakeClient({
        "/": Resp(200, '<a href="https://discord.gg/abcd1234">join</a>'),
        "/wp-login.php": Resp(200, "see https://t.me/+AbCdEfGh12 for help"),
    })
    f = _only(_run("admin_invite_link_scan", client))
    assert f.severity == "low" and f.title.startswith("2 chat-invite")
    assert {i["platform"] for i in f.extra["invites"]} == {"Discord", "Telegram"}


def test_admin_invite_links_clean_page_is_silent():
    assert _run("admin_invite_link_scan", FakeClient({"/": Resp(200, "<p>hello</p>")})) == []


# --------------------------------------------------------------------------
# ai_agent_webhook_leak
# --------------------------------------------------------------------------
def test_ai_agent_webhook_open_relay_is_high():
    client = FakeClient({("POST", "/wp-json/mwai/v1/chats/submit"): Resp(200, '{"reply":"hi"}')})
    f = _only(_run("ai_agent_webhook_leak", client))
    assert f.severity == "high" and f.extra == {"endpoint": "/wp-json/mwai/v1/chats/submit", "status": 200}


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_ai_agent_webhook_gated_or_broken_relay_is_silent(status):
    client = FakeClient({("POST", "/wp-json/mwai/v1/chats/submit"): Resp(status, "x")})
    assert _run("ai_agent_webhook_leak", client) == []


def test_ai_agent_webhook_inline_key_leak_but_not_site_internal():
    leak = FakeClient({"/": Resp(200, "<script>var c={apiUrl: 'https://api.openai.com/v1'};</script>")})
    f = _only(_run("ai_agent_webhook_leak", leak))
    assert f.severity == "medium" and f.extra["leak"] == "https://api.openai.com/v1"
    internal = FakeClient({"/": Resp(200, "<script>var c={apiUrl: '/wp-json/chat'};</script>")})
    assert _run("ai_agent_webhook_leak", internal) == []


# --------------------------------------------------------------------------
# ai_chatbot_endpoint_leak
# --------------------------------------------------------------------------
def test_ai_chatbot_endpoint_leaks_pii_json_is_critical():
    body = '{"messages": [{"user_email": "a@b.co", "message_text": "hi"}]}'
    client = FakeClient({"/wp-json/tidio/v1/messages": Resp(200, body)})
    f = _only(_run("ai_chatbot_endpoint_leak", client))
    assert f.severity == "critical"
    assert f.extra["exposed_endpoints"] == ["/wp-json/tidio/v1/messages"]
    assert f.url == "https://example.com"


def test_ai_chatbot_endpoint_ignores_html_and_markerless_json():
    client = FakeClient({
        "/wp-json/tidio/v1/messages": Resp(200, "<html>\"email\"</html>"),
        "/wp-json/tidio/v1/conversations": Resp(200, '{"ok": true}'),
        "/wp-json/ai-engine/v1/chat": Resp(403, '{"email": 1}'),
    })
    assert _run("ai_chatbot_endpoint_leak", client) == []


# --------------------------------------------------------------------------
# ai_plugin_prompt_storage
# --------------------------------------------------------------------------
def test_ai_plugin_fingerprint_in_html_is_high():
    client = FakeClient({"/": Resp(200, '<link href="/wp-content/plugins/ai-engine/x.css">')})
    f = _only(_run("ai_plugin_prompt_storage", client))
    assert f.severity == "high" and "AI Engine" in f.title
    assert f.extra["category"] == "prompt-injection"


def test_ai_plugin_route_403_counts_as_detection():
    client = FakeClient({"/wp-json/mwai/v1/health": Resp(403, "no")})
    f = _only(_run("ai_plugin_prompt_storage", client))
    assert f.severity == "high" and f.extra["plugins_detected"]


def test_ai_plugin_clean_site_is_silent():
    assert _run("ai_plugin_prompt_storage", FakeClient({"/": Resp(200, "<p>blog</p>")})) == []


# --------------------------------------------------------------------------
# algolia_elastic_frontend_keys
# --------------------------------------------------------------------------
def _padded_b64(payload: str) -> str:
    for pad in range(3):
        s = base64.b64encode((payload + " " * pad).encode()).decode()
        if "=" in s:
            return s
    raise AssertionError("could not build a padded base64 key")


def test_algolia_admin_acl_key_is_critical():
    key = _padded_b64('{"acl":["addObject","deleteObject"],"validUntil":1700000000}')
    assert len(key) > 24
    client = FakeClient({"/": Resp(200, f'<script>var algoliaApiKey: "{key}";</script>')})
    f = _only(_run("algolia_elastic_frontend_keys", client))
    assert f.severity == "critical" and f.extra["admin_acl"] is True


def test_algolia_search_only_key_is_low():
    key = _padded_b64('{"acl":["search"],"validUntil":1700000000}')
    client = FakeClient({"/": Resp(200, f'var algoliaApiKey = "{key}";')})
    f = _only(_run("algolia_elastic_frontend_keys", client))
    assert f.severity == "low" and f.extra["admin_acl"] is False


def test_algolia_short_opaque_key_is_low_and_missing_key_is_silent():
    low = _run("algolia_elastic_frontend_keys", FakeClient({"/": Resp(200, 'algoliaApiKey: "abcdEFGH12345678abcd"')}))
    assert _sevs(low) == ["low"]
    assert _run("algolia_elastic_frontend_keys", FakeClient({"/": Resp(200, "<p>none</p>")})) == []


# --------------------------------------------------------------------------
# amp_transitional_redirect
# --------------------------------------------------------------------------
def _amp_client(probe: Resp) -> FakeClient:
    def route(_m, path, _kw):
        return probe if path.startswith("/?amp") else Resp(200, '<link rel="amphtml" href="/amp/">')
    return FakeClient(default=route)


def test_amp_redirect_to_external_host_is_medium_and_stops_after_first_hit():
    client = _amp_client(Resp(302, "", {"location": "https://wpsecscan-probe.example/"}))
    f = _only(_run("amp_transitional_redirect", client))
    assert f.severity == "medium"
    assert len([c for c in client.calls if c[1].startswith("/?amp")]) == 1


def test_amp_probe_with_ordinary_200_is_silent():
    assert _run("amp_transitional_redirect", _amp_client(Resp(200, "ok"))) == []


def test_amp_site_without_amp_markup_is_not_probed():
    client = FakeClient({"/": Resp(200, "<p>plain</p>")})
    assert _run("amp_transitional_redirect", client) == []
    assert client.calls == [("GET", "/")]


# --------------------------------------------------------------------------
# app_passwords_stale_audit
# --------------------------------------------------------------------------
def _ap_client(aps: list[dict]) -> FakeClient:
    return FakeClient({
        "/wp-json/wp/v2/users?context=edit&per_page=100": Resp(200, json_body=[{"id": 7, "name": "Ann"}]),
        "/wp-json/wp/v2/users/7/application-passwords": Resp(200, json_body=aps),
    })


def _now_iso(days_ago: int = 0) -> str:
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def test_app_passwords_noop_without_session():
    client = FakeClient()
    assert _run("app_passwords_stale_audit", client) == []
    assert client.calls == []


def test_app_passwords_old_and_unused_is_medium():
    ctx = _ctx(auth_cookies={"a": "b"})
    f = _only(_run("app_passwords_stale_audit",
                   _ap_client([{"name": "ci", "created": "2019-01-01T00:00:00", "last_used": None}]), ctx))
    assert f.severity == "medium" and f.extra["user_id"] == 7 and f.extra["age_days"] > 180


def test_app_passwords_recent_and_used_is_clean_but_recent_unused_is_low():
    ctx = _ctx(companion_token="t")
    fresh = {"name": "ci", "created": _now_iso(1), "last_used": _now_iso(0)}
    assert _run("app_passwords_stale_audit", _ap_client([fresh]), ctx) == []
    never_used = {"name": "ci", "created": _now_iso(1), "last_used": None}
    assert _sevs(_run("app_passwords_stale_audit", _ap_client([never_used]), ctx)) == ["low"]


def test_app_passwords_tolerates_junk_payloads():
    ctx = _ctx(shared={"authenticated": True})
    junk_users = FakeClient({"/wp-json/wp/v2/users?context=edit&per_page=100": Resp(200, "not json")})
    assert _run("app_passwords_stale_audit", junk_users, ctx) == []
    not_list = FakeClient({"/wp-json/wp/v2/users?context=edit&per_page=100": Resp(200, json_body={"a": 1})})
    assert _run("app_passwords_stale_audit", not_list, ctx) == []
    assert _run("app_passwords_stale_audit", _ap_client([1, "x", None]), ctx) == []


def test_app_passwords_days_since_helper():
    m = _mod("app_passwords_stale_audit")
    assert m._days_since(None) is None
    assert m._days_since("garbage") is None
    assert m._days_since("2000-01-01T00:00:00Z") > 365


# --------------------------------------------------------------------------
# block_bindings_exposure
# --------------------------------------------------------------------------
def test_block_bindings_custom_source_is_medium():
    html = '<!-- wp:paragraph {"metadata":{"bindings":{"content":{"source":"acme/secret"}}}} -->'
    f = _only(_run("block_bindings_exposure", FakeClient({"/": Resp(200, html)})))
    assert f.severity == "medium" and f.extra["custom_sources"] == ["acme/secret"]


def test_block_bindings_core_source_and_plain_page_are_silent():
    html = '<!-- wp:paragraph {"metadata":{"bindings":{"content":{"source":"core/post-meta"}}}} -->'
    assert _run("block_bindings_exposure", FakeClient({"/": Resp(200, html)})) == []
    assert _run("block_bindings_exposure", FakeClient({"/": Resp(200, "<p>x</p>")})) == []


# --------------------------------------------------------------------------
# block_style_variations_url
# --------------------------------------------------------------------------
@pytest.mark.parametrize("host", ["169.254.169.254", "127.0.0.1:8080", "10.0.0.5", "192.168.1.9", "localhost"])
def test_block_style_internal_urls_are_medium(host):
    html = f'<div style="background:url(http://{host}/x.png)"></div>'
    f = _only(_run("block_style_variations_url", FakeClient({"/": Resp(200, html)})))
    assert f.severity == "medium"


def test_block_style_public_urls_are_silent():
    html = '<div style="background:url(https://cdn.example.net/a.png)"></div>'
    assert _run("block_style_variations_url", FakeClient({"/": Resp(200, html)})) == []


# --------------------------------------------------------------------------
# bucket_shadow_takeover (builds its own httpx client)
# --------------------------------------------------------------------------
def test_bucket_shadow_slug_helper():
    m = _mod("bucket_shadow_takeover")
    assert m._slug_from_host("example.com") == "example"
    assert m._slug_from_host("www.acme.co.uk") == "acme"
    assert m._slug_from_host("blog.acme.co.uk") == "acme"
    assert m._slug_from_host("deep.shop.acme.com") == "deep"


def test_bucket_shadow_unregistered_s3_name_is_high(net):
    def handler(req):
        if req.url.host == "acme-uploads.s3.amazonaws.com":
            return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
        return httpx.Response(404, text="nothing")
    net.handler = handler
    f = _only(_run("bucket_shadow_takeover", FakeClient(base_url="https://www.acme.com")))
    assert f.severity == "high" and f.extra == {"bucket": "acme-uploads", "provider": "S3"}
    assert all(r.url.host.endswith(("s3.amazonaws.com", "storage.googleapis.com")) for r in net.seen)


def test_bucket_shadow_gcs_marker_is_detected(net):
    net.handler = lambda req: (
        httpx.Response(404, text="The specified bucket does not exist")
        if req.url.host == "acme-media.storage.googleapis.com" else httpx.Response(404, text="x"))
    f = _only(_run("bucket_shadow_takeover", FakeClient(base_url="https://acme.com")))
    assert f.extra["provider"] == "GCS" and f.extra["bucket"] == "acme-media"


def test_bucket_shadow_all_404_and_connect_errors_are_silent(net):
    assert _run("bucket_shadow_takeover", FakeClient(base_url="https://acme.com")) == []

    def boom(req):
        raise httpx.ConnectError("down", request=req)
    net.handler = boom
    assert _run("bucket_shadow_takeover", FakeClient(base_url="https://acme.com")) == []


def test_bucket_shadow_short_slug_makes_no_requests(net):
    assert _run("bucket_shadow_takeover", FakeClient(base_url="https://ab.io")) == []
    assert net.seen == []


# --------------------------------------------------------------------------
# companion_v13 / companion_v14 (module-level httpx calls)
# --------------------------------------------------------------------------
def _json_routes(table: dict[str, object]):
    def handler(req: httpx.Request) -> httpx.Response:
        body = table.get(req.url.path)
        if body is None:
            return httpx.Response(404, text="nope")
        return httpx.Response(200, json=body)
    return handler


def test_companion_v13_noop_without_token(net):
    assert _run("companion_v13", FakeClient(), _ctx()) == []
    assert net.seen == []


def test_companion_v13_all_sections_fire(net):
    net.handler = _json_routes({
        "/wp-json/wpsecscan/v1/users-with-app-passwords": {
            "supported": True,
            "users": [{"user_login": "bob", "app_passwords": [
                {"name": "ci", "created": "2019-01-01T00:00:00", "last_used": None, "uuid": "u1"}]}]},
        "/wp-json/wpsecscan/v1/recent-uploads": {"uploads": [
            {"ext": "php", "path": "2026/10/shell.php", "mtime": "t", "size": 5},
            {"ext": "jpg", "path": "2026/10/a.jpg", "mtime": "t", "size": 9}]},
        "/wp-json/wpsecscan/v1/wp-cron-event-history": {"source": "derived", "count": 3},
        "/wp-json/wpsecscan/v1/admin-notice-content": {"count": 25, "notices": [{"name": "n1"}]},
        "/wp-json/wpsecscan/v1/site-health-tests": {"supported": True, "tests": [
            {"name": "a", "label": "A", "status": "critical", "badge": "x"},
            {"name": "b", "status": "recommended"},
            {"name": "c", "status": "good"}]},
    })
    out = _run("companion_v13", FakeClient(), _ctx(companion_token="tok"))
    assert sorted(_sevs(out)) == ["high", "high", "info", "low", "low", "medium"]
    assert any("web-shell" in f.title for f in out if f.severity == "high")
    assert {r.headers["x-wpsecscan-token"] for r in net.seen} == {"tok"}
    assert {r.url.host for r in net.seen} == {"example.com"}


def test_companion_v13_below_threshold_payloads_are_silent(net):
    net.handler = _json_routes({
        "/wp-json/wpsecscan/v1/users-with-app-passwords": {"supported": True, "users": [
            {"user_login": "bob", "app_passwords": [{"name": "n", "created": _now_iso(1)}]}]},
        "/wp-json/wpsecscan/v1/recent-uploads": {"uploads": [{"ext": "png", "path": "a.png"}]},
        "/wp-json/wpsecscan/v1/wp-cron-event-history": {"source": "logger", "count": 1},
        "/wp-json/wpsecscan/v1/admin-notice-content": {"count": 5, "notices": []},
        "/wp-json/wpsecscan/v1/site-health-tests": {"supported": True, "tests": [{"name": "c", "status": "good"}]},
    })
    assert _run("companion_v13", FakeClient(), _ctx(companion_token="tok")) == []


def test_companion_v13_hit_handles_non_json_and_transport_errors(net):
    m = _mod("companion_v13")
    net.handler = lambda req: httpx.Response(200, text="<html>")
    assert asyncio.run(m._hit("https://example.com", "/x", "t")) is None

    def boom(req):
        raise httpx.ConnectError("down", request=req)
    net.handler = boom
    assert asyncio.run(m._hit("https://example.com", "/x", "t")) is None
    assert _run("companion_v13", FakeClient(), _ctx(companion_token="tok")) == []


def test_companion_v13_days_since_helper():
    m = _mod("companion_v13")
    assert m._days_since("") is None
    assert m._days_since("nope") is None
    assert m._days_since("2000-01-01T00:00:00Z") > 365


def test_companion_v14_noop_without_token(net):
    assert _run("companion_v14", FakeClient(), _ctx()) == []
    assert net.seen == []


def test_companion_v14_all_sections_fire(net):
    net.handler = _json_routes({
        "/wp-json/wpsecscan/v1/plugin-license-keys": {
            "count": 2, "license_options": [{"option_name": "x_license", "looks_empty": True},
                                             {"option_name": "y_license", "looks_empty": False}]},
        "/wp-json/wpsecscan/v1/active-network-requests": {"count_24h": 150, "top_hosts": {"evil.example": 99}},
        "/wp-json/wpsecscan/v1/page-cache-info": {
            "plugins_detected": ["WP Rocket"], "cache_size_bytes": 1073741824,
            "cache_dir": "/c", "cache_file_count": 2},
        "/wp-json/wpsecscan/v1/database-encoding": {
            "mismatched_count": 1, "connection_charset": "utf8",
            "non_utf8mb4_tables": [{"table": "wp_x", "collation": "latin1_swedish_ci"}]},
        "/wp-json/wpsecscan/v1/customizer-bookmarks": {
            "count": 1, "theme": "t", "risky_modifiers": [{"key": "k", "value_excerpt": "<script>"}]},
        "/wp-json/wpsecscan/v1/widget-block-html": {
            "count": 1, "risky_widgets": [{"option_name": "widget_text", "value_excerpt": "<iframe>"}]},
    })
    out = _run("companion_v14", FakeClient(), _ctx(companion_token="tok"))
    assert sorted(_sevs(out)) == ["high", "high", "info", "low", "medium", "medium"]
    assert {r.url.host for r in net.seen} == {"example.com"}


def test_companion_v14_quiet_payloads_are_silent(net):
    net.handler = _json_routes({
        "/wp-json/wpsecscan/v1/plugin-license-keys": {"count": 1, "license_options": [
            {"option_name": "x", "looks_empty": False}]},
        "/wp-json/wpsecscan/v1/active-network-requests": {"count_24h": 3},
        "/wp-json/wpsecscan/v1/page-cache-info": {"plugins_detected": []},
        "/wp-json/wpsecscan/v1/database-encoding": {"mismatched_count": 0},
        "/wp-json/wpsecscan/v1/customizer-bookmarks": {"count": 2, "risky_modifiers": []},
        "/wp-json/wpsecscan/v1/widget-block-html": {"count": 0},
    })
    assert _run("companion_v14", FakeClient(), _ctx(companion_token="tok")) == []


# --------------------------------------------------------------------------
# composer_npm_typosquat
# --------------------------------------------------------------------------
def test_typosquat_levenshtein_helper():
    f = _mod("composer_npm_typosquat")._levenshtein1
    assert f("reakt", "react") is True       # substitution
    assert f("reacts", "react") is True      # insertion
    assert f("reac", "react") is True        # deletion
    assert f("react", "react") is False      # exact is not a near-match
    assert f("raect", "react") is False      # transposition = 2 edits
    assert f("lodashes", "lodash") is False


def test_typosquat_candidate_in_lock_file_is_medium():
    client = FakeClient({"/package-lock.json": Resp(200, '{"dependencies":{"reakt":"1.0.0"}}')})
    f = _only(_run("composer_npm_typosquat", client))
    assert f.severity == "medium" and f.title.endswith("/package-lock.json")
    assert {"dep": "reakt", "near": "react"} in f.extra["candidates"]


def test_typosquat_exact_known_good_and_missing_locks_are_silent():
    client = FakeClient({"/package-lock.json": Resp(200, '{"dependencies":{"react":"1.0.0"}}')})
    assert _run("composer_npm_typosquat", client) == []
    assert _run("composer_npm_typosquat", FakeClient()) == []


# --------------------------------------------------------------------------
# cookie_banner_cosmetic_vs_blocking
# --------------------------------------------------------------------------
_BANNER = "<div id='cmplz-cookiebanner'>cookiebot</div>"


def _banner_client(vanilla_cookies, reject_cookies) -> FakeClient:
    def route(_m, _p, kw):
        rejecting = "Cookie" in (kw.get("headers") or {})
        pairs = reject_cookies if rejecting else vanilla_cookies
        return Resp(200, _BANNER, [("set-cookie", f"{c}=1; Path=/") for c in pairs])
    return FakeClient(default=route)


def test_cookie_banner_none_detected_is_info():
    f = _only(_run("cookie_banner_cosmetic_vs_blocking", FakeClient({"/": Resp(200, "<p>x</p>")})))
    assert f.severity == "info" and "no cookie banner" in f.title


def test_cookie_banner_cosmetic_when_trackers_survive_reject():
    f = _only(_run("cookie_banner_cosmetic_vs_blocking", _banner_client(["_ga", "_fbp"], ["_ga"])))
    assert f.severity == "medium" and "COSMETIC" in f.title and "_ga" in f.evidence


def test_cookie_banner_blocking_when_trackers_stop():
    f = _only(_run("cookie_banner_cosmetic_vs_blocking", _banner_client(["_ga"], [])))
    assert f.severity == "info" and "blocking" in f.title


def test_cookie_banner_none_responses():
    assert _run("cookie_banner_cosmetic_vs_blocking", FakeClient(default=None)) == []


# --------------------------------------------------------------------------
# cookie_consent_desync
# --------------------------------------------------------------------------
def test_cookie_consent_desync_tracking_cookie_pre_consent_is_medium():
    client = FakeClient({"/": Resp(200, "x", [("set-cookie", "_ga=GA1.2; Path=/"), ("set-cookie", "sid=1")])})
    f = _only(_run("cookie_consent_desync", client))
    assert f.severity == "medium" and f.extra["cookies_pre_consent"] == ["_ga"]
    assert client.kwargs[0]["headers"] == {"Cookie": ""}


def test_cookie_consent_desync_benign_cookies_and_none():
    assert _run("cookie_consent_desync", FakeClient({"/": Resp(200, "x", [("set-cookie", "sid=1")])})) == []
    assert _run("cookie_consent_desync", FakeClient({"/": Resp(200, "x")})) == []
    assert _run("cookie_consent_desync", FakeClient(default=None)) == []


# --------------------------------------------------------------------------
# core_checksums
# --------------------------------------------------------------------------
_PHP_GOOD = b"<?php // genuine core file\n"
_VER_CTX = {"shared": {"wp_version": "6.5.2"}}


def _patch_checksums(monkeypatch, table):
    async def fake(_version):
        return table
    monkeypatch.setattr(_mod("core_checksums"), "_fetch_checksums", fake)


def test_core_checksums_no_version_is_silent():
    client = FakeClient()
    assert _run("core_checksums", client) == []
    assert client.calls == []


def test_core_checksums_tampered_core_file_is_critical(monkeypatch):
    _patch_checksums(monkeypatch, {"wp-includes/version.php": hashlib.sha256(_PHP_GOOD).hexdigest()})
    client = FakeClient({"/wp-includes/version.php": Resp(200, content=b"<?php eval($_POST['x']);")})
    f = _only(_run("core_checksums", client, _ctx(**_VER_CTX)))
    assert f.severity == "critical" and "1 file(s)" in f.title
    assert f.extra["mismatches"][0]["path"] == "/wp-includes/version.php"


def test_core_checksums_matching_html_and_missing_files_are_silent(monkeypatch):
    digest = hashlib.sha256(_PHP_GOOD).hexdigest()
    _patch_checksums(monkeypatch, {"wp-includes/version.php": digest, "wp-includes/load.php": digest,
                                   "wp-login.php": digest})
    client = FakeClient({
        "/wp-includes/version.php": Resp(200, content=_PHP_GOOD),            # identical
        "/wp-includes/load.php": Resp(200, "<html>rendered</html>"),         # not PHP source -> skipped
        "/wp-login.php": Resp(404, "nf"),
    })
    assert _run("core_checksums", client, _ctx(**_VER_CTX)) == []


def test_core_checksums_empty_manifest_is_silent():
    # autouse stub returns None
    assert _run("core_checksums", FakeClient(), _ctx(**_VER_CTX)) == []


def test_core_checksums_fetch_checksums_real_path(net, monkeypatch):
    net.handler = lambda req: httpx.Response(200, json={"checksums": {"a.php": "ab"}})
    assert asyncio.run(_REAL_FETCH_CHECKSUMS("6.5.2")) == {"a.php": "ab"}
    assert net.seen[0].url.host == "api.wordpress.org"
    net.handler = lambda req: httpx.Response(200, json=["not", "a", "dict"])
    assert asyncio.run(_REAL_FETCH_CHECKSUMS("6.5.2")) is None
    net.handler = lambda req: httpx.Response(200, text="<<not json")
    assert asyncio.run(_REAL_FETCH_CHECKSUMS("6.5.2")) is None
    net.handler = lambda req: httpx.Response(500, text="x")
    assert asyncio.run(_REAL_FETCH_CHECKSUMS("6.5.2")) is None
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    n_before = len(net.seen)
    assert asyncio.run(_REAL_FETCH_CHECKSUMS("6.5.2")) is None
    assert len(net.seen) == n_before


# --------------------------------------------------------------------------
# crypto_payment_callback_audit
# --------------------------------------------------------------------------
def test_crypto_callback_open_200_is_critical():
    client = FakeClient({("POST", "/wp-json/blockonomics/v1/callback"): Resp(200, "received")})
    f = _only(_run("crypto_payment_callback_audit", client))
    assert f.severity == "critical" and "blockonomics" in f.title
    assert client.kwargs[0]["json"]  # spoof body was sent


def test_crypto_callback_400_ok_body_is_high():
    client = FakeClient({("POST", "/wp-json/blockonomics/v1/callback"): Resp(400, "ok but bad")})
    assert _sevs(_run("crypto_payment_callback_audit", client)) == ["high"]


@pytest.mark.parametrize("resp", [Resp(404, ""), Resp(401, "x"), Resp(403, "x"),
                                  Resp(200, "invalid signature"), Resp(200, "HMAC missing"), Resp(500, "boom")])
def test_crypto_callback_challenged_or_absent_is_silent(resp):
    client = FakeClient({("POST", "/wp-json/blockonomics/v1/callback"): resp})
    assert _run("crypto_payment_callback_audit", client) == []


# --------------------------------------------------------------------------
# csp_report_endpoint (HEADs the report endpoint with its own httpx client)
# --------------------------------------------------------------------------
def _csp_client(csp: str | None) -> FakeClient:
    headers = {"Content-Security-Policy": csp} if csp else {}
    return FakeClient({"/": Resp(200, "x", headers)})


def test_csp_report_uri_404_is_medium(net):
    net.handler = lambda req: httpx.Response(404)
    f = _only(_run("csp_report_endpoint", _csp_client("default-src 'self'; report-uri https://r.example.net/csp")))
    assert f.severity == "medium" and "HTTP 404" in f.title
    assert [(r.method, str(r.url)) for r in net.seen] == [("HEAD", "https://r.example.net/csp")]


def test_csp_report_uri_reachable_is_info_and_relative_resolves_to_target(net):
    net.handler = lambda req: httpx.Response(204)
    f = _only(_run("csp_report_endpoint", _csp_client("default-src 'self'; report-uri /csp-report")))
    assert f.severity == "info" and "reachable (204)" in f.title
    assert str(net.seen[0].url) == "https://example.com/csp-report"


def test_csp_report_uri_unreachable_is_medium(net):
    def boom(req):
        raise httpx.ConnectError("down", request=req)
    net.handler = boom
    f = _only(_run("csp_report_endpoint", _csp_client("report-uri https://r.example.net/csp")))
    assert f.severity == "medium" and "unreachable" in f.title


def test_csp_without_report_endpoint_or_without_csp_is_silent(net):
    assert _run("csp_report_endpoint", _csp_client(None)) == []
    assert _run("csp_report_endpoint", _csp_client("default-src 'self'")) == []
    assert _run("csp_report_endpoint", _csp_client("default-src 'self'; report-to csp-group")) == []
    assert net.seen == []


# --------------------------------------------------------------------------
# ct_log_recent_certs (module-level crt.sh query)
# --------------------------------------------------------------------------
def _ts(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def _ct_rows(n: int, days_ago: int = 1) -> list[dict]:
    return [{"name_value": f"s{i}.acme.com", "issuer_name": "C=US, O=Let's Encrypt",
             "entry_timestamp": _ts(days_ago)} for i in range(n)]


def test_ct_recent_certs_few_is_info(net):
    net.handler = lambda req: httpx.Response(200, json=_ct_rows(2))
    f = _only(_run("ct_log_recent_certs", FakeClient(), _ctx(target="https://www.acme.com/")))
    assert f.severity == "info" and "2 cert(s)" in f.title and "*.acme.com" in f.title
    assert net.seen[0].url.host == "crt.sh"


def test_ct_recent_certs_five_or_more_is_low(net):
    net.handler = lambda req: httpx.Response(200, json=_ct_rows(5))
    assert _sevs(_run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com"))) == ["low"]


def test_ct_recent_certs_old_empty_error_and_bad_host_are_silent(net):
    net.handler = lambda req: httpx.Response(200, json=_ct_rows(3, days_ago=90))
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com")) == []
    net.handler = lambda req: httpx.Response(200, json=[])
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com")) == []
    net.handler = lambda req: httpx.Response(503, text="x")
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com")) == []
    net.handler = lambda req: httpx.Response(200, text="<<")
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com")) == []
    n = len(net.seen)
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="http://localhost")) == []
    assert len(net.seen) == n


def test_ct_recent_certs_no_network_env(net, monkeypatch):
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    assert _run("ct_log_recent_certs", FakeClient(), _ctx(target="https://acme.com")) == []
    assert net.seen == []


# --------------------------------------------------------------------------
# ct_log_shadow_cert (live-issuer probe stubbed; crt.sh via MockTransport)
# --------------------------------------------------------------------------
def _stub_issuer(monkeypatch, issuer: str):
    async def fake(_host):
        return issuer
    monkeypatch.setattr(_mod("ct_log_shadow_cert"), "_live_cert_issuer", fake)


def test_ct_shadow_foreign_issuer_is_high(net, monkeypatch):
    _stub_issuer(monkeypatch, "Let's Encrypt")
    net.handler = lambda req: httpx.Response(200, json=[
        {"issuer_name": "C=GB, O=Sectigo Limited", "common_name": "example.com", "not_before": "2026-10-01"},
        {"issuer_name": "C=US, O=Let's Encrypt", "common_name": "example.com", "not_before": "2026-09-01"},
        {"issuer_name": "C=US, O=DigiCert", "common_name": "other.net", "name_value": "other.net"},
    ])
    f = _only(_run("ct_log_shadow_cert", FakeClient(), _ctx()))
    assert f.severity == "high" and "Sectigo" in f.title
    assert f.extra["live_issuer"] == "Let's Encrypt"


def test_ct_shadow_same_issuer_only_is_silent(net, monkeypatch):
    _stub_issuer(monkeypatch, "Let's Encrypt")
    net.handler = lambda req: httpx.Response(200, json=[
        {"issuer_name": "C=US, O=Let's Encrypt", "common_name": "example.com"}])
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []


def test_ct_shadow_unprobeable_tls_makes_no_lookup(net):
    # autouse stub: live issuer == ""
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []
    assert net.seen == []


def test_ct_shadow_bad_crtsh_responses_are_silent(net, monkeypatch):
    _stub_issuer(monkeypatch, "Let's Encrypt")
    net.handler = lambda req: httpx.Response(500, text="x")
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []
    net.handler = lambda req: httpx.Response(200, json={"not": "a list"})
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []
    net.handler = lambda req: httpx.Response(200, text="<<")
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []
    net.handler = lambda req: httpx.Response(200, json=[1, "x", None])
    assert _run("ct_log_shadow_cert", FakeClient(), _ctx()) == []


# --------------------------------------------------------------------------
# db_trigger_audit
# --------------------------------------------------------------------------
_TRIG = "/wp-json/wpsecscan-companion/v1/triggers"


def test_db_trigger_suspicious_statement_is_critical():
    body = {"triggers": [{"name": "t_evil", "statement": "SET @x = sys_exec('id')"},
                         {"name": "t_ok", "statement": "SET NEW.updated = NOW()"}]}
    f = _only(_run("db_trigger_audit", FakeClient({_TRIG: Resp(200, json_body=body)})))
    assert f.severity == "critical" and "t_evil" in f.title and "sys_exec" in f.extra["hit_patterns"]


def test_db_trigger_benign_and_empty_are_info():
    ok = {"triggers": [{"name": "t_ok", "statement": "SET NEW.updated = NOW()"}]}
    f = _only(_run("db_trigger_audit", FakeClient({_TRIG: Resp(200, json_body=ok)})))
    assert f.severity == "info" and "none matched" in f.title
    f = _only(_run("db_trigger_audit", FakeClient({_TRIG: Resp(200, json_body={"triggers": []})})))
    assert f.severity == "info" and "clean" in f.title


def test_db_trigger_auth_required_missing_and_garbage():
    f = _only(_run("db_trigger_audit", FakeClient({_TRIG: Resp(403, "no")})))
    assert f.severity == "info" and "requires auth" in f.title
    assert _run("db_trigger_audit", FakeClient()) == []
    assert _run("db_trigger_audit", FakeClient({_TRIG: Resp(500, "x")})) == []
    assert _run("db_trigger_audit", FakeClient({_TRIG: Resp(200, "not json")})) == []
    f = _only(_run("db_trigger_audit", FakeClient({_TRIG: Resp(200, json_body=[1, 2])})))
    assert "clean" in f.title  # non-dict JSON is treated as "no triggers"


# --------------------------------------------------------------------------
# debug_log_pii_sniff
# --------------------------------------------------------------------------
_LOG = "/wp-content/debug.log"


def test_debug_log_email_is_high():
    log = "[12-Oct-2026 10:00:00 UTC] PHP Notice: user jane.doe@acme-corp.org failed login"
    f = _only(_run("debug_log_pii_sniff", FakeClient({_LOG: Resp(200, log)})))
    assert f.severity == "high" and f.extra["emails_found"] == 1 and f.extra["cc_shaped"] == 0


def test_debug_log_card_shaped_digits_are_critical():
    log = "[12-Oct-2026 10:00:00 UTC] gateway payload card=4539 1488 0343 6467 exp=12/29 ok"
    f = _only(_run("debug_log_pii_sniff", FakeClient({_LOG: Resp(200, log)})))
    assert f.severity == "critical" and f.extra["cc_shaped"] >= 1


def test_debug_log_ip_only_is_high():
    f = _only(_run("debug_log_pii_sniff",
                   FakeClient({_LOG: Resp(200, "[12-Oct-2026] request from 203.0.113.9 blocked by rule")})))
    assert f.severity == "high" and f.extra["ips_found"] == 1


@pytest.mark.parametrize("body", [
    "tiny",                                                                    # empty-ish
    "[12-Oct-2026] mail from noreply@wordpress.org queued for sending ok",     # noise-only email
    "[12-Oct-2026] nothing sensitive here, just a plain notice line",          # no PII
])
def test_debug_log_without_pii_is_silent(body):
    assert _run("debug_log_pii_sniff", FakeClient({_LOG: Resp(200, body)})) == []


def test_debug_log_not_exposed_is_silent():
    assert _run("debug_log_pii_sniff", FakeClient()) == []


# --------------------------------------------------------------------------
# email_obfuscation_audit
# --------------------------------------------------------------------------
def test_email_obfuscation_defeated_by_raw_address_is_low():
    html = '<script src="/cdn-cgi/scripts/email-decode.min.js"></script> mail bob@acme-corp.org'
    f = _only(_run("email_obfuscation_audit", FakeClient({"/": Resp(200, html)})))
    assert f.severity == "low" and f.extra["leak_count"] == 1
    assert f.extra["libraries"] == ["Cloudflare email protection"]


def test_email_obfuscation_clean_is_info_and_no_library_is_silent():
    only_lib = '<a href="/cdn-cgi/l/email-protection#abc">[email protected]</a> hello@example.com'
    f = _only(_run("email_obfuscation_audit", FakeClient({"/": Resp(200, only_lib)})))
    assert f.severity == "info" and f.extra["leak_count"] == 0
    assert _run("email_obfuscation_audit", FakeClient({"/": Resp(200, "mail bob@acme-corp.org")})) == []


# --------------------------------------------------------------------------
# font_library_api_ssrf
# --------------------------------------------------------------------------
def test_font_library_readable_endpoints_are_low_each():
    client = FakeClient({"/wp-json/wp/v2/font-families": Resp(200, "[]"),
                         "/wp-json/wp/v2/font-collections": Resp(200, "[]")})
    out = _run("font_library_api_ssrf", client)
    assert _sevs(out) == ["low", "low"]
    assert [f.extra["path"] for f in out] == ["/wp-json/wp/v2/font-families", "/wp-json/wp/v2/font-collections"]


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_font_library_gated_is_silent(status):
    assert _run("font_library_api_ssrf", FakeClient({"/wp-json/wp/v2/font-families": Resp(status, "x")})) == []


# --------------------------------------------------------------------------
# form_builder_upload_bypass
# --------------------------------------------------------------------------
@pytest.mark.parametrize("html,name", [
    ('<link href="/wp-content/plugins/wpforms-lite/x.css"><script id="wpforms-frontend">', "wpforms"),
    ('<script src="/wp-content/plugins/gravityforms/js/a.js">', "gravity-forms"),
    ('<div class="frm_forms">', "formidable"),
])
def test_form_builder_fingerprint_is_medium(html, name):
    f = _only(_run("form_builder_upload_bypass", FakeClient({"/": Resp(200, html)})))
    assert f.severity == "medium" and name in f.extra["plugins"]


def test_form_builder_absent_is_silent():
    assert _run("form_builder_upload_bypass", FakeClient({"/": Resp(200, "<p>blog</p>")})) == []


# --------------------------------------------------------------------------
# gdpr_dsr_endpoint_enum
# --------------------------------------------------------------------------
_AJAX = ("POST", "/wp-admin/admin-ajax.php")


def test_gdpr_dsr_unprotected_action_is_medium_per_action():
    client = FakeClient({_AJAX: Resp(200, '{"success":true}')})
    out = _run("gdpr_dsr_endpoint_enum", client)
    assert _sevs(out) == ["medium"] * 4
    assert {f.extra["action"] for f in out} == {
        "wp-privacy-export-personal-data", "wp-privacy-erase-personal-data",
        "wp-privacy-erasure-request", "wp-privacy-request"}
    assert client.kwargs[0]["data"]["action"] == "wp-privacy-export-personal-data"


@pytest.mark.parametrize("resp", [Resp(200, "-1"), Resp(200, "0\n"), Resp(200, "Bad nonce"),
                                  Resp(200, "permission denied"), Resp(403, "forbidden"), Resp(404, "x")])
def test_gdpr_dsr_wp_native_rejections_are_silent(resp):
    assert _run("gdpr_dsr_endpoint_enum", FakeClient({_AJAX: resp})) == []


def test_gdpr_dsr_digit_zero_substring_is_not_treated_as_a_wp_rejection():
    # B27 regression: "100" contains "0" but is not the bare WP "0" token.
    assert len(_run("gdpr_dsr_endpoint_enum", FakeClient({_AJAX: Resp(200, "100")}))) == 4


# --------------------------------------------------------------------------
# github_actions_workflow_leak
# --------------------------------------------------------------------------
_WORKFLOW = "name: Deploy\non: push\njobs:\n  d:\n    steps:\n      - run: x ${{ secrets.DEPLOY_KEY }}\n"


def test_github_workflow_leak_is_medium_and_stops_at_first_hit():
    client = FakeClient({"/.github/workflows/ci.yml": Resp(200, _WORKFLOW),
                         "/.github/workflows/deploy.yml": Resp(200, _WORKFLOW)})
    f = _only(_run("github_actions_workflow_leak", client))
    assert f.severity == "medium" and f.extra["secrets_leaked"] == ["DEPLOY_KEY"]
    assert f.extra["path"] == "/.github/workflows/ci.yml"
    assert ("GET", "/.github/workflows/deploy.yml") not in client.calls


def test_github_workflow_generic_200_and_404_are_silent():
    client = FakeClient(default=Resp(200, "<html><body>Not found</body></html>"))
    assert _run("github_actions_workflow_leak", client) == []
    assert _run("github_actions_workflow_leak", FakeClient()) == []


# --------------------------------------------------------------------------
# gtm_inventory
# --------------------------------------------------------------------------
def test_gtm_single_container_is_info_and_multiple_is_low():
    one = _only(_run("gtm_inventory", FakeClient({"/": Resp(200, "<script>GTM-ABC1234</script>")})))
    assert one.severity == "info" and one.extra["gtm_ids"] == ["GTM-ABC1234"]
    two = _only(_run("gtm_inventory", FakeClient({"/": Resp(200, "GTM-ABC1234 and GTM-ZZZ9999 GTM-ABC1234")})))
    assert two.severity == "low" and len(two.extra["gtm_ids"]) == 2


def test_gtm_absent_is_silent():
    assert _run("gtm_inventory", FakeClient({"/": Resp(200, "<p>no tags GTM-1</p>")})) == []


# --------------------------------------------------------------------------
# headless_cors_lockdown
# --------------------------------------------------------------------------
def test_headless_cors_wildcard_is_high():
    client = FakeClient({"/wp-json/": Resp(200, "{}", {"Access-Control-Allow-Origin": "*"})})
    f = _only(_run("headless_cors_lockdown", client))
    assert f.severity == "high" and "1 endpoint" in f.title
    assert client.kwargs[0]["headers"]["Origin"].startswith("https://wpsecscan-cors-probe")


def test_headless_cors_reflected_origin_and_credentials_combo():
    def reflect(_m, _p, kw):
        return Resp(200, "{}", {"Access-Control-Allow-Origin": kw["headers"]["Origin"]})
    out = _run("headless_cors_lockdown", FakeClient(default=reflect))
    assert _sevs(out) == ["high"] and "3 endpoint" in out[0].title
    combo = FakeClient({"/wp-json/": Resp(200, "{}", {"Access-Control-Allow-Origin": "*",
                                                      "Access-Control-Allow-Credentials": "true"})})
    assert "Credentials=true" in _only(_run("headless_cors_lockdown", combo)).evidence


def test_headless_cors_restrictive_and_failing_requests_are_info():
    strict = FakeClient(default=Resp(200, "{}", {"Access-Control-Allow-Origin": "https://www.example.com"}))
    f = _only(_run("headless_cors_lockdown", strict))
    assert f.severity == "info" and "restrictive" in f.title
    assert _sevs(_run("headless_cors_lockdown", FakeClient(default=None))) == ["info"]
    assert _sevs(_run("headless_cors_lockdown", _RaisingClient())) == ["info"]


# --------------------------------------------------------------------------
# headless_vercel_netlify_detect
# --------------------------------------------------------------------------
@pytest.mark.parametrize("headers,platform", [
    ({"x-vercel-id": "iad1::abc"}, "Vercel"),
    ({"x-nf-request-id": "01H"}, "Netlify"),
    ({"x-netlify-version": "1"}, "Netlify"),
    ({"cf-pages": "1"}, "Cloudflare Pages"),
    ({"server": "Vercel"}, "Vercel"),
    ({"server": "Netlify"}, "Netlify"),
])
def test_headless_platform_with_open_rest_is_medium(headers, platform):
    client = FakeClient({"/": Resp(200, "x", headers), "/wp-json/": Resp(200, "{}")})
    f = _only(_run("headless_vercel_netlify_detect", client))
    assert f.severity == "medium" and f.extra == {"platform": platform}


def test_headless_no_platform_or_closed_rest_is_silent():
    plain = FakeClient({"/": Resp(200, "x", {"server": "nginx"}), "/wp-json/": Resp(200, "{}")})
    assert _run("headless_vercel_netlify_detect", plain) == []
    assert plain.calls == [("GET", "/")]
    closed = FakeClient({"/": Resp(200, "x", {"x-vercel-id": "a"}), "/wp-json/": Resp(404, "nf")})
    assert _run("headless_vercel_netlify_detect", closed) == []
    assert _run("headless_vercel_netlify_detect", FakeClient(default=None)) == []
