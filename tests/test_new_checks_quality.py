"""Targeted tests for the 5 new checks added in the Quality-Over-Quantity round.

These don't try to be exhaustive — they pin the headline behavior so future
refactors can't silently regress the "no findings" vs "real finding" cases.
"""
from __future__ import annotations

import asyncio

import importlib

server_timing = importlib.import_module("wpsecscan.checks.server_timing")
wp_rest_methods = importlib.import_module("wpsecscan.checks.wp_rest_methods")
source_maps = importlib.import_module("wpsecscan.checks.source_maps")

from tests.conftest import FakeClient, FakeResponse  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ---------- server_timing ----------

def test_server_timing_no_leak_is_info():
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(status_code=200, headers={"Content-Type": "text/html"}),
    })
    findings = run(server_timing.check(client, _ctx()))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_server_timing_debug_headers_are_medium():
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(
            status_code=200,
            headers={
                "X-Debug-Token-Link": "/_profiler/abc123",
                "X-AspNet-Version": "4.0.30319",
            },
        ),
    })
    findings = run(server_timing.check(client, _ctx()))
    assert "medium" in {f.severity for f in findings}


def test_server_timing_fingerprint_headers_are_low():
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(
            status_code=200,
            headers={"Server-Timing": "db;dur=12", "X-Request-ID": "abc-123"},
        ),
    })
    findings = run(server_timing.check(client, _ctx()))
    severities = {f.severity for f in findings}
    assert "low" in severities
    assert "medium" not in severities


# ---------- wp_rest_methods ----------

def test_rest_methods_no_write_methods_is_info():
    findings = run(wp_rest_methods.check(FakeClient(), _ctx()))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_rest_methods_write_method_advertised_is_low_or_medium():
    client = FakeClient(responses={
        ("OPTIONS", "/wp-json/wp/v2/posts"): FakeResponse(
            status_code=200, headers={"Allow": "GET, POST"}
        ),
    })
    findings = run(wp_rest_methods.check(client, _ctx()))
    assert any(f.severity in ("low", "medium") for f in findings)


def test_rest_methods_delete_method_is_medium():
    client = FakeClient(responses={
        ("OPTIONS", "/wp-json/wp/v2/posts"): FakeResponse(
            status_code=200, headers={"Allow": "GET, POST, DELETE"}
        ),
    })
    findings = run(wp_rest_methods.check(client, _ctx()))
    severities = {f.severity for f in findings if f.severity != "info"}
    assert "medium" in severities


# ---------- source_maps ----------

def test_source_maps_clean_is_info():
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(status_code=200, text="<html><body>hi</body></html>"),
        ("GET", "/wp-login.php"): FakeResponse(status_code=200, text="<html></html>"),
        ("GET", "/?p=1"): FakeResponse(status_code=200, text="<html></html>"),
    })
    findings = run(source_maps.check(client, _ctx()))
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_source_maps_protocol_relative_url_does_not_crash():
    """Regression: //cdn/app.js used to NameError because js_url_full was never assigned."""
    html = '<html><script src="//cdn.example.com/app.js"></script></html>'
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(status_code=200, text=html),
        ("GET", "/wp-login.php"): FakeResponse(status_code=200, text="<html></html>"),
        ("GET", "/?p=1"): FakeResponse(status_code=200, text="<html></html>"),
        # protocol-relative URL resolves to https:// — FakeClient returns None for unknown paths
    })
    # Should not raise; produces an "info" finding since the JS isn't actually reachable
    findings = run(source_maps.check(client, _ctx()))
    assert findings  # any non-crash result is acceptable


def test_source_maps_served_map_is_high():
    html = '<html><script src="/app.js"></script></html>'
    js = "console.log(1);\n//# sourceMappingURL=app.js.map\n"
    map_body = '{"version":3,"sources":["src/a.js"]}'
    client = FakeClient(responses={
        ("GET", "/"): FakeResponse(status_code=200, text=html),
        ("GET", "/wp-login.php"): FakeResponse(status_code=200, text="<html></html>"),
        ("GET", "/?p=1"): FakeResponse(status_code=200, text="<html></html>"),
        ("GET", "https://example.com/app.js"): FakeResponse(status_code=200, text=js),
        ("GET", "https://example.com/app.js.map"): FakeResponse(status_code=200, text=map_body),
    })
    findings = run(source_maps.check(client, _ctx()))
    assert any(f.severity == "high" for f in findings)


# ---------- inventory + data-file sanity ----------

def test_quick_fixes_has_verify_for_all_new_checks():
    import json
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "quick_fixes.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    for check_name in ("dns_security", "source_maps", "js_supply_chain", "server_timing", "wp_rest_methods"):
        assert check_name in data["verify"], f"missing verify entry for {check_name}"
        assert isinstance(data["verify"][check_name], list)
        assert len(data["verify"][check_name]) >= 2


def test_signature_counts_meet_target():
    import json
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "exploit_signatures.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    real_sigs = [s for s in data["signatures"] if "id" in s]
    assert len(real_sigs) >= 300, f"expected >=300, got {len(real_sigs)}"


def test_payload_counts_meet_target():
    from wpsecscan.payloads import load_payloads
    ps = load_payloads()
    assert len(ps) >= 220, f"expected >=220, got {len(ps)}"


def test_global_scope_signatures_have_required_fields():
    import json
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "exploit_signatures.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    globals_ = [s for s in data["signatures"] if s.get("scope") == "global"]
    assert len(globals_) >= 5
    for s in globals_:
        assert s.get("path"), f"global sig {s.get('id')} missing path"
        assert s.get("match"), f"global sig {s.get('id')} missing match"
        assert s.get("title"), f"global sig {s.get('id')} missing title"
