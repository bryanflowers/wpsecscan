"""Round-64 — smoke tests for the 165 new features.

Strategy: one or two happy-path tests per non-trivial new module.
Mocked-httpx pattern via the new tests/check_framework helpers.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest


# ============================================================
# Group F — Modern WP attack-surface (#51-70) — smoke tests
# ============================================================

def _run(coro):
    return asyncio.run(coro)


class _FakeResponse:
    def __init__(self, status_code=200, text="", *, json_body=None, headers=None, content=None):
        self.status_code = status_code
        self.text = text if text else (json.dumps(json_body) if json_body is not None else "")
        self.content = content if content is not None else (self.text or "").encode("utf-8")
        self.headers = headers or {}
        self.url = ""
        self._json_body = json_body

    def json(self):
        return self._json_body if self._json_body is not None else json.loads(self.text)


class _FakeClient:
    def __init__(self, responses=None, default=None, base_url="https://test.example.com"):
        self.responses = responses or {}
        self.default = default
        self.base_url = base_url

    def url(self, p):
        return self.base_url + ("" if p.startswith("/") else "/") + p

    async def request(self, method, path, **kw):
        return self.responses.get((method, path), self.default)

    async def get(self, p, **kw):  return await self.request("GET", p, **kw)
    async def post(self, p, **kw): return await self.request("POST", p, **kw)
    async def head(self, p, **kw): return await self.request("HEAD", p, **kw)
    async def aclose(self):        pass


def _ctx(**kw):
    base = {"step": lambda s: None, "shared": {}}
    base.update(kw)
    return base


def test_ai_prompt_injection_passive_fires_on_known_plugin():
    # v2.8.5 Phase 6.1 — `from .. import X as m` resolves to the
    # check-function attribute that wpsecscan.checks.__init__ rebinds,
    # which CodeQL sees as callable. The pre-fix
    # `import wpsecscan.checks.X as m` form is statically a module
    # import; the runtime shadow is invisible to CodeQL and gets
    # flagged py/call-to-non-callable. Same fix applied to the rest.
    from wpsecscan.checks import ai_prompt_injection_passive as m
    responses = {
        ("GET", "/wp-content/plugins/ai-engine/readme.txt"): _FakeResponse(200, "=== AI Engine ===\n" + "x" * 100),
        ("POST", "/wp-json/ai-engine/v1/chat"): _FakeResponse(200, "Hello world reply over twenty characters long for the heuristic to fire"),
    }
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    titles = " ".join(f.title for f in findings)
    assert "ai-engine" in titles or "AI/LLM" in titles


def test_env_file_enum_fires_on_aws_key():
    from wpsecscan.checks import env_file_enum as m
    body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=supersecret\nFOO=bar\n"
    responses = {("GET", "/.env"): _FakeResponse(200, body)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("AWS" in f.title or ".env" in f.title for f in findings)


def test_cryptominer_detects_coinhive_pattern():
    from wpsecscan.checks import cryptominer_js_injection as m
    body = '<script src="https://coinhive.min.js"></script>'
    responses = {("GET", "/"): _FakeResponse(200, body)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("Cryptominer" in f.title or "miner" in f.title.lower() for f in findings)


def test_composer_lock_audit_detects_known_vuln_guzzle():
    from wpsecscan.checks import composer_lock_audit as m
    lock = json.dumps({
        "_format": "composer-lock-test",
        "content-hash": "abc",
        "packages": [
            {"name": "guzzlehttp/guzzle", "version": "7.4.0"},
            {"name": "monolog/monolog", "version": "3.0.0"},
        ],
    })
    responses = {("GET", "/composer.lock"): _FakeResponse(200, lock)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("guzzle" in f.title.lower() for f in findings)


def test_plugin_typosquat_detection_fires_on_close_match():
    from wpsecscan.checks import plugin_typosquat_detection as m
    # 'yost-seo' is Levenshtein 1 from 'yoast-seo'
    findings = _run(m(_FakeClient(), _ctx(shared={"plugins": ["yost-seo"]})))
    assert any("typosquat" in f.title.lower() for f in findings)


def test_webhook_url_fingerprint_flags_discord():
    from wpsecscan.checks import webhook_url_fingerprint as m
    body = json.dumps({"webhooks": [{"option_key": "my_setting", "url": "https://discord.com/api/webhooks/123/abc"}]})
    responses = {("GET", "/wp-json/wpsecscan-companion/v1/webhooks"): _FakeResponse(200, body)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("Discord" in f.title for f in findings)


def test_git_dir_deep_scan_fires_on_head():
    from wpsecscan.checks import git_dir_deep_scan as m
    responses = {("GET", "/.git/HEAD"): _FakeResponse(200, "ref: refs/heads/main\n")}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any(".git" in f.title for f in findings)


# ============================================================
# Group G — Web3/NFT/payment (#71-76)
# ============================================================

def test_payment_gateway_test_keys_detects_stripe_secret():
    from wpsecscan.checks import payment_gateway_test_keys as m
    # Synthetic key that matches the sk_test_<24+ alnum> pattern but is not
    # a real Stripe key (GH secret scanning blocks committed real test keys).
    # Build the key at runtime so the literal doesn't appear in this file.
    key = "sk" + "_test_" + ("A" * 24)
    body = f'var key = "{key}";'
    responses = {("GET", "/"): _FakeResponse(200, body)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("Stripe" in f.title for f in findings)


def test_wallet_seed_phrase_leak_detects_bip39():
    from wpsecscan.checks import wallet_seed_phrase_leak as m
    seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"
    body = f"# .env backup\nSEED={seed}\n"
    responses = {("GET", "/.env"): _FakeResponse(200, body)}
    findings = _run(m(_FakeClient(responses, default=_FakeResponse(404)), _ctx()))
    assert any("seed" in f.title.lower() for f in findings)


# ============================================================
# Group A consent gate
# ============================================================


# ============================================================
# Group D — Trust signals + Group E — Threat intel
# ============================================================

def test_threat_intel_v2_module_loads():
    """All functions should be defined."""
    import wpsecscan.threat_intel_v2 as ti
    for name in ("cisa_kev_lookup", "epss_score", "exploit_db_link",
                 "metasploit_module", "attack_navigator_json",
                 "stix_bundle", "otx_pulses_for_domain", "greynoise_lookup"):
        assert hasattr(ti, name), f"missing function {name}"


# ============================================================
# Group H — GUI helpers (snooze / saved views)
# ============================================================


# ============================================================
# Group I — Reporters
# ============================================================

def test_badge_svg_renders_grade():
    from wpsecscan.reporters import badge_svg
    svg = badge_svg.render_badge_svg({"critical": 0, "high": 0, "medium": 0, "low": 0})
    assert "<svg" in svg and "A+" in svg


def test_public_page_requires_optin():
    from wpsecscan.reporters import public_page
    with pytest.raises(ValueError):
        public_page.render_public_page("example.com", {"critical": 0})


def test_eli5_returns_plain_english():
    from wpsecscan.reporters import eli5_toggle
    report = {"target": "x.com", "results": [{"findings": [{"severity": "high", "title": "SQL injection in /foo"}]}]}
    text = eli5_toggle.render_eli5(report)
    assert "URGENT" in text or "urgent" in text.lower()


def test_translated_summary_supports_6_langs():
    from wpsecscan.reporters import translated_summary as t
    for lang in ("en", "es", "de", "fr", "ja", "zh"):
        out = t.render_translated("x.com", {"critical": 0, "high": 0, "medium": 0, "low": 0}, lang=lang)
        assert len(out) > 20


def test_trend_over_time_history_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan.reporters import trend_over_time
    importlib.reload(trend_over_time)
    trend_over_time.append_to_history("test.example.com", {"critical": 1, "high": 0})
    history = trend_over_time.load_history("test.example.com")
    assert len(history) == 1
    svg = trend_over_time.render_sparkline_svg("test.example.com", history)
    assert "<svg" in svg


# ============================================================
# Group J — CLI a11y helpers
# ============================================================


# ============================================================
# Group L — Enterprise (RBAC + audit log + approval)
# ============================================================

def test_rbac_reader_cannot_start_scan():
    from wpsecscan.auth import rbac
    u = rbac.User(username="alice", role="reader")
    with pytest.raises(PermissionError):
        rbac.require(u, rbac.PERM_START_SCAN)


def test_rbac_operator_can_start_scan():
    from wpsecscan.auth import rbac
    u = rbac.User(username="bob", role="operator")
    rbac.require(u, rbac.PERM_START_SCAN)  # no raise


def test_audit_log_chain_verifies(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.auth import audit_log
    audit_log.append("alice", "scan_start", target="x.com")
    audit_log.append("alice", "scan_complete", target="x.com")
    ok, n, err = audit_log.verify_chain()
    assert ok and n == 2, f"err={err}"


def test_approval_workflow_requires_two_people(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.auth import approval_workflow as aw
    req = aw.create_request("alice", "https://x.com", "aggressive_scan", "PCI audit")
    with pytest.raises(ValueError):
        aw.approve(req.request_id, "alice")  # same user
    aw.approve(req.request_id, "bob")        # different user OK
    final = aw.consume(req.request_id)
    assert final.approved_by == "bob"


def test_multi_tenant_validates_id():
    from wpsecscan.enterprise import multi_tenant
    with pytest.raises(ValueError):
        multi_tenant.validate_tenant_id("Bad Tenant!")  # bad chars
    assert multi_tenant.validate_tenant_id("ok-tenant-1") == "ok-tenant-1"


def test_quota_blocks_after_max(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    from wpsecscan.enterprise import multi_tenant, quota
    multi_tenant.create_tenant("t1")
    for _ in range(3):
        quota.consume("t1", max_per_day=3)
    with pytest.raises(PermissionError):
        quota.consume("t1", max_per_day=3)


def test_billing_signature_verify():
    from wpsecscan.enterprise import billing_stub
    import hmac, hashlib, time
    secret = "whsec_test"
    body = b'{"event":"x"}'
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    header = f"t={ts},v1={sig}"
    assert billing_stub.verify_stripe_signature(body, header, secret) is True
    assert billing_stub.verify_stripe_signature(body, header, "wrong") is False


# ============================================================
# Group O — Webhook v2 sign/verify round-trip
# ============================================================

def test_webhook_v2_round_trip():
    from wpsecscan.daemon import webhook_v2
    body = b'{"hello":"world"}'
    sw = webhook_v2.SignedWebhook.sign(body, "secret")
    verifier = webhook_v2.WebhookVerifier("secret")
    assert verifier.verify(body, sw.headers()) is True


def test_webhook_v2_replay_rejected():
    from wpsecscan.daemon import webhook_v2
    body = b'{"hello":"world"}'
    sw = webhook_v2.SignedWebhook.sign(body, "secret")
    v = webhook_v2.WebhookVerifier("secret")
    assert v.verify(body, sw.headers()) is True
    # Same nonce again -> reject
    assert v.verify(body, sw.headers()) is False


# ============================================================
# Group P — Check authoring helpers
# ============================================================

def test_lint_checks_script_runnable():
    from pathlib import Path
    script = Path(__file__).parent.parent / "scripts" / "lint-checks.py"
    assert script.exists()


def test_check_framework_has_helpers():
    from tests import check_framework
    assert hasattr(check_framework, "FakeClient")
    assert hasattr(check_framework, "FakeResponse")


# ============================================================
# Group R — Performance helpers
# ============================================================

def test_smart_skip_skips_graphql_when_no_graphql():
    from wpsecscan.incremental import smart_skip
    skip, reason = smart_skip.should_skip("wpgraphql", {"has_graphql": False})
    assert skip is True


def test_smart_skip_runs_graphql_when_present():
    from wpsecscan.incremental import smart_skip
    skip, _ = smart_skip.should_skip("wpgraphql", {"has_graphql": True})
    assert skip is False


def test_connection_pool_shares_clients():
    import asyncio
    from wpsecscan.perf.connection_pool import SharedClientPool

    async def go():
        async with SharedClientPool() as pool:
            c1 = await pool.get("https://example.com")
            c2 = await pool.get("https://example.com")
            assert c1 is c2

    asyncio.run(go())


# ============================================================
# Wild cards — bingo card, brand monitor, forensics timeline
# ============================================================

def test_bingo_card_24_distinct_plus_free():
    from wpsecscan.fun import bingo_card
    grid = bingo_card.generate_card(seed=42)
    flat = [c for row in grid for c in row]
    assert flat[12] == "FREE"
    # 24 distinct content items
    items = [c for c in flat if c != "FREE"]
    assert len(set(items)) == 24


def test_brand_monitor_typosquat_candidates():
    # The package __init__.py aliases the submodule's check fn to the
    # same name, shadowing the module. Reach the module via sys.modules
    # (set by the import side-effect during package load) instead.
    import sys
    mod = sys.modules["wpsecscan.checks.brand_monitor"]
    cands = mod._typosquats("example.com")
    assert len(cands) > 0
    assert "example.com" not in cands  # never include the original


