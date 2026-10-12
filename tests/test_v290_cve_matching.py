"""v2.9.0 W2d/W2e/W2f — CVE version matching, KEV/EPSS failure signalling.

All data is mocked: no feed, no host, no network.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from tests.conftest import FakeClient, FakeResponse
from wpsecscan import db as vulndb
from wpsecscan.db import Vuln, affected, find_for, ver_lt, ver_lte


def run(coro):
    return asyncio.run(coro)


def _vuln(slug="foo", fixed_in="3.0", affected_from="", affected_to="", to_inclusive=False,
          cve="CVE-2024-0001"):
    return Vuln(slug=slug, type="plugin", title="t", severity="high", cve=cve, cvss=None,
                fixed_in=fixed_in, affected_from=affected_from, affected_to=affected_to,
                to_inclusive=to_inclusive, references=[], description="")


# ---------------------------------------------------------------- W2d: ordering

def test_prerelease_tags_natural_sort():
    assert ver_lt("1.0-rc9", "1.0-rc10")
    assert not ver_lt("1.0-rc10", "1.0-rc9")
    assert ver_lt("1.0-alpha", "1.0-beta")
    assert ver_lt("1.0-beta", "1.0-rc1")
    assert ver_lt("1.0-beta2", "1.0-beta10")
    assert not ver_lt("1.0-rc1", "1.0-RC1")


def test_prerelease_below_its_release():
    assert ver_lt("1.0-rc1", "1.0")
    assert not ver_lt("1.0", "1.0-rc1")
    assert ver_lt("1.0-rc1", "1.0.0")


def test_numeric_components_compare_as_ints():
    assert ver_lt("6.4", "6.10")
    assert not ver_lt("6.10", "6.4")


def test_trailing_zeros_not_significant():
    assert ver_lte("2.0.0", "2.0")
    assert ver_lte("2.0", "2.0.0")
    assert ver_lte("2", "2.0.0")
    assert not ver_lt("2.0.0", "2.0")
    assert not ver_lt("2.0", "2.0.0")
    assert vulndb.ver_parts("2.0.0") == vulndb.ver_parts("2.0") == vulndb.ver_parts("2")
    assert ver_lte("1.9", "2.0.0")
    assert not ver_lte("2.0.1", "2.0")


def test_exclusive_upper_bound_with_extra_zero_component():
    v = _vuln(fixed_in="2.0", affected_to="2.0", to_inclusive=False)
    assert not affected("2.0.0", v)
    assert not affected("2.0", v)
    assert affected("1.9.9", v)
    assert affected("2.0-rc1", v)  # pre-release of the fixed version is still vulnerable
    vi = _vuln(fixed_in="", affected_to="2.0", to_inclusive=True)
    assert affected("2.0.0", vi)
    assert not affected("2.0.1", vi)


# ------------------------------------------------- W2d: unversioned never matches

@pytest.mark.parametrize("bad", [None, "", "unknown", "trunk", "n/a"])
def test_non_numeric_version_matches_nothing(bad):
    vulns = [_vuln(fixed_in="3.0"), _vuln(fixed_in="", affected_to="9.9", to_inclusive=True),
             _vuln(fixed_in="")]  # last one: "all versions"
    assert find_for(vulns, "plugin", "foo", bad) == []
    for v in vulns:
        assert affected(bad, v) is False


def test_numeric_version_still_matches():
    vulns = [_vuln(fixed_in="3.0")]
    assert len(find_for(vulns, "plugin", "foo", "2.9")) == 1
    assert find_for(vulns, "plugin", "foo", "3.0") == []


def test_plugins_check_readme_without_numeric_tag_stores_none(ctx):
    from wpsecscan.checks.plugins import check
    client = FakeClient(responses={
        "/": FakeResponse(text='<script src="/wp-content/plugins/foo/a.js"></script>'),
        "/wp-content/plugins/foo/readme.txt": FakeResponse(text="=== Foo ===\nStable tag: trunk\n"),
    })
    findings = run(check(client, ctx))
    assert ctx["shared"]["plugins"] == {"foo": None}
    # Display layer still says "unknown".
    listing = next(f for f in findings if "plugin(s) discovered" in f.title)
    assert "foo  (version: unknown)" in listing.evidence
    readme = next(f for f in findings if "expose readme.txt" in f.title)
    assert "foo: version unknown" in readme.evidence


def _patch_db(monkeypatch, vulns):
    monkeypatch.setattr(vulndb, "load_local", lambda: (vulns, 0, "cache"))


@pytest.mark.parametrize("ver", [None, "unknown", ""])
def test_plugin_cves_unversioned_plugin_yields_no_cve_findings(monkeypatch, ctx, ver):
    from wpsecscan.checks.plugin_cves import check
    _patch_db(monkeypatch, [_vuln(slug="foo", fixed_in="3.0"),
                            _vuln(slug="foo", fixed_in="", cve="CVE-2024-0002")])
    ctx["shared"]["plugins"] = {"foo": ver}
    findings = run(check(FakeClient(), ctx))
    assert not any("Known vulnerability" in f.title for f in findings)
    assert not any(f.extra.get("cve") for f in findings)
    assert "foo" not in ctx["shared"].get("cve_matched_slugs", set())
    # The report says why: low-confidence "version not detected" finding.
    assert any("version not detected" in f.title and f.severity == "low" for f in findings)


def test_plugin_cves_versioned_plugin_still_matches(monkeypatch, ctx):
    from wpsecscan.checks.plugin_cves import check
    _patch_db(monkeypatch, [_vuln(slug="foo", fixed_in="3.0")])
    ctx["shared"]["plugins"] = {"foo": "2.9"}
    findings = run(check(FakeClient(), ctx))
    assert any("Known vulnerability in foo 2.9" in f.title for f in findings)


def test_signature_max_version_honours_trailing_zero():
    from wpsecscan.checks.plugin_cves import _run_sigs_for
    sig = {"id": "sig-1", "path": "/probe", "match": "status_eq", "match_value": 200,
           "max_version": "2.0", "title": "probe"}
    out: list = []
    client = FakeClient(responses={"/probe": FakeResponse(status_code=200, text="ok")})
    run(_run_sigs_for(client, [sig], "2.0.0", out, lambda _s: None))
    assert len(out) == 1  # 2.0.0 <= 2.0, so the probe must run (was skipped before)
    out2: list = []
    run(_run_sigs_for(client, [sig], "2.0.1", out2, lambda _s: None))
    assert out2 == []


# ----------------------------------------------------------------- W2e: KEV

def _kev_report():
    from wpsecscan.models import CheckResult, Finding, ScanReport
    f1 = Finding(severity="high", title="a", evidence="", remediation="", url="",
                 extra={"cve": "CVE-2024-0001"})
    f2 = Finding(severity="low", title="b", evidence="", remediation="", url="", extra={})
    return ScanReport(target="https://example.com", scanned_at="", duration_ms=0,
                      results=[CheckResult(check_id="x", check_name="x", findings=[f1, f2])])


def test_filter_findings_to_kev_unavailable_returns_none_and_keeps_findings(monkeypatch):
    from wpsecscan import kev
    monkeypatch.setattr(kev, "fetch_kev_cves", lambda **kw: set())
    report = _kev_report()
    assert kev.filter_findings_to_kev(report) is None
    assert len(report.results[0].findings) == 2


def test_filter_findings_to_kev_zero_match_is_zero_not_none(monkeypatch):
    from wpsecscan import kev
    monkeypatch.setattr(kev, "fetch_kev_cves", lambda **kw: {"CVE-1999-9999"})
    report = _kev_report()
    assert kev.filter_findings_to_kev(report) == 0
    assert report.results[0].findings == []


def test_filter_findings_to_kev_match_counts(monkeypatch):
    from wpsecscan import kev
    monkeypatch.setattr(kev, "fetch_kev_cves", lambda **kw: {"CVE-2024-0001"})
    report = _kev_report()
    assert kev.filter_findings_to_kev(report) == 1
    assert report.results[0].findings[0].extra["kev_match"] == ["CVE-2024-0001"]


def test_json_report_marks_kev_and_epss_failure(monkeypatch):
    from wpsecscan.integrations import cisa_kev, epss
    from wpsecscan.reporters import json_out
    monkeypatch.setattr(cisa_kev, "load_kev_set", lambda *a, **k: set())

    def boom(_cves):
        raise OSError("network down")
    monkeypatch.setattr(epss, "lookup_scores", boom)
    d = json.loads(json_out.render(_kev_report()))
    ti = d["threat_intel"]
    assert ti["cisa_kev_actively_exploited"] is None
    assert "unavailable" in ti["kev_error"]
    assert "OSError" in ti["epss_error"]


def test_json_report_kev_checked_none_is_empty_list(monkeypatch):
    from wpsecscan.integrations import cisa_kev, epss
    from wpsecscan.reporters import json_out
    monkeypatch.setattr(cisa_kev, "load_kev_set", lambda *a, **k: {"CVE-1999-9999"})
    monkeypatch.setattr(epss, "lookup_scores",
                        lambda c: {"CVE-2024-0001": {"epss": 0.1, "percentile": 0.5, "date": "d"}})
    d = json.loads(json_out.render(_kev_report()))
    ti = d["threat_intel"]
    assert ti["cisa_kev_actively_exploited"] == []
    assert "kev_error" not in ti and "epss_error" not in ti


# ----------------------------------------------------------------- W2f: EPSS

def test_epss_failure_not_cached_and_no_stale_poison(monkeypatch, tmp_path):
    from wpsecscan import threat_intel_v2 as ti
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.setattr(ti, "_http_get_json", lambda *a, **k: None)
    assert ti.epss_score("CVE-2024-0001") == {}
    assert not ti._cache_path().exists()
    # Empty-but-successful payload is not cached either.
    monkeypatch.setattr(ti, "_http_get_json", lambda *a, **k: {"data": []})
    assert ti.epss_score("CVE-2024-0001") == {}
    assert not ti._cache_path().exists()


def test_epss_failure_serves_previous_cache_even_if_stale(monkeypatch, tmp_path):
    from wpsecscan import threat_intel_v2 as ti
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    good = {"epss": 0.5, "percentile": 0.9, "date": "2026-10-01"}
    ti._cache_path().write_text(
        json.dumps({"epss:CVE-2024-0001": {"ts": 1, "value": good}}), encoding="utf-8")
    before = ti._cache_path().read_bytes()
    monkeypatch.setattr(ti, "_http_get_json", lambda *a, **k: None)
    assert ti.epss_score("CVE-2024-0001") == good
    assert ti._cache_path().read_bytes() == before


def test_epss_poisoned_empty_entry_is_refetched(monkeypatch, tmp_path):
    from wpsecscan import threat_intel_v2 as ti
    import time
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    ti._cache_path().write_text(
        json.dumps({"epss:CVE-2024-0001": {"ts": int(time.time()), "value": {}}}), encoding="utf-8")
    payload = {"data": [{"epss": "0.25", "percentile": "0.8", "date": "2026-10-12"}]}
    monkeypatch.setattr(ti, "_http_get_json", lambda *a, **k: payload)
    got = ti.epss_score("CVE-2024-0001")
    assert got["epss"] == 0.25
    stored = json.loads(ti._cache_path().read_text(encoding="utf-8"))
    assert stored["epss:CVE-2024-0001"]["value"]["percentile"] == 0.8
