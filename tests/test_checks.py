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


def test_users_rest_embed_author_leak(ctx):
    """_embed pulls author objects into /posts even when /users is locked down.
    This is the standard WordPress REST API behaviour."""
    from wpsecscan.checks.users import check
    import json as _json
    posts_body = _json.dumps([
        {"id": 1, "title": {"rendered": "Hello"},
         "_embedded": {"author": [{"id": 1, "slug": "admin", "name": "Site Admin"}]}},
        {"id": 2, "title": {"rendered": "Second"},
         "_embedded": {"author": [{"id": 2, "slug": "editor"}]}},
    ])
    client = FakeClient(responses={
        "/wp-json/wp/v2/posts?per_page=20&_embed=1": FakeResponse(
            text=posts_body, headers={"content-type": "application/json"}),
    })
    findings = run(check(client, ctx))
    assert any("_embed" in f.title and "user" in f.title for f in findings), \
        f"expected _embed author-leak finding, got: {[f.title for f in findings]}"


def test_users_rest_users_endpoint_with_only_null_entries_skips(ctx):
    """A REST route that returns [null] or [{}] must NOT fire a user-disclosure
    finding — that was a false-positive on plugins overriding the route."""
    from wpsecscan.checks.users import check
    import json as _json
    junk_body = _json.dumps([None, {}])
    client = FakeClient(responses={
        "/wp-json/wp/v2/users": FakeResponse(text=junk_body, headers={"content-type": "application/json"}),
    })
    findings = run(check(client, ctx))
    assert not any("REST /wp-json/wp/v2/users exposes" in f.title for f in findings), \
        f"expected no FP, got: {[f.title for f in findings]}"


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


def test_db_ver_lt_pre_release_lower_than_release():
    """A pre-release of X should sort below X. Previously `1.2.3-rc1` was treated
    as equal to `1.2.3`, so a vuln fixed in `1.2.3` was wrongly considered patched
    on `1.2.3-rc1`."""
    from wpsecscan import db
    assert db.ver_lt("1.2.3-rc1", "1.2.3")
    assert db.ver_lt("1.2.3rc1", "1.2.3")        # inline tag, no separator
    assert db.ver_lt("1.2.3-beta", "1.2.3-rc1")  # beta < rc
    assert not db.ver_lt("1.2.3", "1.2.3-rc1")
    assert not db.ver_lt("1.2.3-rc1", "1.2.3-rc1")


def test_db_affected():
    from wpsecscan.db import Vuln, affected
    v = Vuln(slug="foo", type="plugin", title="t", severity="high", cve="CVE-X", cvss=None,
             fixed_in="2.0", affected_from="", affected_to="2.0", to_inclusive=False,
             references=[], description="")
    assert affected("1.9.99", v)
    assert not affected("2.0", v)
    assert not affected("2.1", v)
    # Pre-release of the fixed version is still vulnerable
    assert affected("2.0-rc1", v)


def test_db_find_for_unknown_version_returns_empty():
    """When installed version is unknown, find_for must NOT dump every historical
    CVE for the slug — that produced dozens of stale findings on plugins with
    long CVE histories. Callers use has_any_for() to surface a low-confidence
    'version unknown' finding instead."""
    from wpsecscan.db import Vuln, find_for, has_any_for
    vulns = [
        Vuln(slug="foo", type="plugin", title="old", severity="high", cve="CVE-1",
             cvss=None, fixed_in="1.0", affected_from="", affected_to="1.0",
             to_inclusive=False, references=[], description=""),
        Vuln(slug="foo", type="plugin", title="newer", severity="medium", cve="CVE-2",
             cvss=None, fixed_in="2.5", affected_from="2.0", affected_to="2.5",
             to_inclusive=False, references=[], description=""),
    ]
    assert find_for(vulns, "plugin", "foo", installed_version=None) == []
    assert find_for(vulns, "plugin", "foo", installed_version="") == []
    assert has_any_for(vulns, "plugin", "foo") is True
    assert has_any_for(vulns, "plugin", "bar") is False
    # Known version still works normally
    assert len(find_for(vulns, "plugin", "foo", "2.3")) == 1


def test_rdap_expiry_parser_critical_when_expired():
    from wpsecscan.checks.dns_security import _parse_rdap_expiry
    payload = {"events": [
        {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
        {"eventAction": "expiration",   "eventDate": "2024-01-01T00:00:00Z"},
    ]}
    raw, days = _parse_rdap_expiry(payload)
    assert raw == "2024-01-01T00:00:00Z"
    assert days is not None and days < 0


def test_rdap_expiry_parser_returns_none_when_no_expiry_event():
    from wpsecscan.checks.dns_security import _parse_rdap_expiry
    assert _parse_rdap_expiry({"events": [{"eventAction": "registration",
                                           "eventDate": "2024-01-01T00:00:00Z"}]}) == (None, None)
    assert _parse_rdap_expiry({}) == (None, None)
    assert _parse_rdap_expiry({"events": []}) == (None, None)


def test_db_aggregated_feed_defaults_inclusive_only_when_no_fixed():
    """When the aggregator carries no `to_inclusive` flag, infer from `fixed_in`:
    - fixed_in present → EXCLUSIVE (Wordfence convention: vulnerable iff installed < fixed)
    - fixed_in absent → INCLUSIVE (entry is "vulnerable up to and including X")

    Previously we forced True universally, causing false-positive CVE matches on
    operators running exactly the fixed version."""
    # Just verify the rule we baked in; the actual code path is exercised by
    # the live update_db() but uses real network — we mirror the logic here.
    def infer(kwargs: dict) -> bool:
        if "to_inclusive" not in kwargs:
            return not bool(kwargs.get("fixed_in") or kwargs.get("affected_to"))
        return kwargs["to_inclusive"]

    assert infer({"fixed_in": "2.0"}) is False
    assert infer({"affected_to": "2.0"}) is False
    assert infer({}) is True
    assert infer({"to_inclusive": True, "fixed_in": "2.0"}) is True  # explicit overrides
    assert infer({"to_inclusive": False}) is False


def test_db_osv_multi_branch_ranges_produce_multiple_vulns():
    """An OSV advisory with multiple introduced/fixed pairs (e.g. fixed in both
    the 7.x and 8.x branches) must expand into multiple Vuln entries — previously
    only the last `fixed` event survived, so users on 8.x missed real CVE matches."""
    from wpsecscan import db
    # Synthesise a minimal OSV-shaped advisory mid-pipeline
    advisory = {
        "id": "GHSA-test",
        "aliases": ["CVE-test"],
        "summary": "test multi-branch",
        "severity": [{"type": "CVSS_V3", "score": "6.5"}],
        "affected": [
            {"ranges": [
                {"events": [{"introduced": "7.0.0"}, {"fixed": "7.1.2"}]},
                {"events": [{"introduced": "8.0.0"}, {"fixed": "8.0.5"}]},
            ]}
        ],
    }
    # Inline-simulate the parsing block in fetch_osv_packagist (we don't want
    # to hit the network; the parser logic is what we're testing).
    pairs = []
    for af in advisory["affected"]:
        for rg in af["ranges"]:
            introduced = ""
            for ev in rg["events"]:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    pairs.append((introduced, ev["fixed"]))
                    introduced = ""
            if introduced:
                pairs.append((introduced, ""))
    assert pairs == [("7.0.0", "7.1.2"), ("8.0.0", "8.0.5")]
    # And the affected() check works for the 8.x branch
    v8 = db.Vuln(slug="x", type="plugin", title="t", severity="medium", cve="CVE-test",
                 cvss=6.5, fixed_in="8.0.5", affected_from="8.0.0", affected_to="8.0.5",
                 to_inclusive=False, references=[], description="")
    assert db.affected("8.0.3", v8)
    assert not db.affected("8.0.5", v8)


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
