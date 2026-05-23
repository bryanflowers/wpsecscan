from __future__ import annotations

import asyncio

from tests.conftest import FakeClient, FakeResponse


def run(coro):
    return asyncio.run(coro)


def test_core_version_meta_generator(ctx):
    from wpsecscan.checks.core_version import check
    html = '<html><meta name="generator" content="WordPress 5.1"></html>'
    client = FakeClient(responses={"/": FakeResponse(text=html)})
    findings = run(check(client, ctx))
    titles = [f.title for f in findings]
    # Either it flags outdated or reports a version disclosed
    assert any("WordPress" in t for t in titles)


def test_users_rest_enumeration(ctx):
    from wpsecscan.checks.users import check
    import json as _json
    rest_body = _json.dumps([{"id": 1, "slug": "admin"}, {"id": 2, "slug": "editor"}])
    client = FakeClient(responses={
        "/wp-json/wp/v2/users": FakeResponse(text=rest_body, headers={"content-type": "application/json"}),
    })
    findings = run(check(client, ctx))
    assert any("REST" in f.title and "user" in f.title for f in findings)


def test_users_no_indicators(ctx):
    from wpsecscan.checks.users import check
    client = FakeClient(responses={})
    findings = run(check(client, ctx))
    assert any("No user enumeration" in f.title for f in findings)


def test_open_redirect_detected(ctx):
    from wpsecscan.checks.open_redirect import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(status_code=302, headers={"location": "https://wpsecscan-redirect-test.invalid/landed"}),
    })
    findings = run(check(client, ctx))
    assert any(f.severity == "medium" and "Open redirect" in f.title for f in findings)


def test_open_redirect_clean(ctx):
    from wpsecscan.checks.open_redirect import check
    client = FakeClient(responses={})
    findings = run(check(client, ctx))
    assert any("No open-redirect vectors" in f.title for f in findings)


def test_directory_listing_detected(ctx):
    from wpsecscan.checks.directory_listing import check
    client = FakeClient(responses={
        "/wp-content/uploads/": FakeResponse(text="<title>Index of /wp-content/uploads/</title>"),
    })
    findings = run(check(client, ctx))
    assert any(f.severity == "high" and "Directory listing" in f.title for f in findings)


def test_http_methods_dangerous(ctx):
    from wpsecscan.checks.http_methods import check
    client = FakeClient(responses={
        ("OPTIONS", "/"): FakeResponse(headers={"allow": "GET, POST, OPTIONS, TRACE"}),
        ("TRACE", "/"): FakeResponse(status_code=200),
    })
    findings = run(check(client, ctx))
    assert any(f.severity in ("medium", "high") and "TRACE" in f.evidence for f in findings)


def test_cookies_missing_flags(ctx):
    from wpsecscan.checks.cookies import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(headers={
            "set-cookie": "wordpress_logged_in_abc=foo; Path=/, wordpress_test_cookie=WP%20Cookie%20check",
        }),
    })
    findings = run(check(client, ctx))
    assert any("missing security flags" in f.title for f in findings)


def test_csp_unsafe_inline(ctx):
    from wpsecscan.checks.csp import check
    client = FakeClient(responses={
        "/": FakeResponse(headers={"content-security-policy": "default-src 'self' 'unsafe-inline'; script-src 'unsafe-eval'"}),
    })
    findings = run(check(client, ctx))
    assert any(f.severity == "high" for f in findings)


def test_robots_sitemap_sensitive(ctx):
    from wpsecscan.checks.robots_sitemap import check
    client = FakeClient(responses={
        "/robots.txt": FakeResponse(text="User-agent: *\nDisallow: /staging/\nDisallow: /admin-internal/"),
    })
    findings = run(check(client, ctx))
    assert any("sensitive-looking" in f.title for f in findings)


def test_db_ver_lt():
    from wpsecscan import db
    assert db.ver_lt("1.2.3", "1.2.4")
    assert not db.ver_lt("2.0.0", "1.9.99")
    assert db.ver_lt("13.1.4", "13.1.5")
    assert not db.ver_lt("13.1.5", "13.1.5")


def test_db_affected():
    from wpsecscan.db import Vuln, affected
    v = Vuln(slug="foo", type="plugin", title="t", severity="high", cve="CVE-X", cvss=None,
             fixed_in="2.0", affected_from="", affected_to="2.0", to_inclusive=False,
             references=[], description="")
    assert affected("1.9.99", v)
    assert not affected("2.0", v)
    assert not affected("2.1", v)


def test_baseline_calibration_stable(ctx):
    from wpsecscan.baseline import calibrate
    body = "X" * 1000
    client = FakeClient(responses={"/": FakeResponse(text=body)})
    cal = run(calibrate(client, "/", samples=3))
    assert cal.samples == 3
    assert cal.max_delta_ratio == 0.0
    assert not cal.is_unstable()


def test_diff_mode_picks_new(tmp_path):
    import json
    from wpsecscan.diff import diff
    old = {"target": "x", "scanned_at": "t1", "results": [
        {"check_id": "c1", "check_name": "C1", "findings": [
            {"severity": "high", "title": "Stable issue", "url": "u", "evidence": "", "remediation": ""}
        ]}
    ]}
    new = {"target": "x", "scanned_at": "t2", "results": [
        {"check_id": "c1", "check_name": "C1", "findings": [
            {"severity": "high", "title": "Stable issue", "url": "u", "evidence": "", "remediation": ""},
            {"severity": "critical", "title": "Brand new!", "url": "v", "evidence": "", "remediation": ""}
        ]}
    ]}
    op = tmp_path / "old.json"; np = tmp_path / "new.json"
    op.write_text(json.dumps(old)); np.write_text(json.dumps(new))
    d = diff(op, np)
    assert len(d["new"]) == 1
    assert d["new"][0]["title"] == "Brand new!"
    assert d["unchanged"] == 1
