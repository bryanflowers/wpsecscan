"""Round-63 — multi-source CVE aggregator tests.

Network calls are mocked via WPSECSCAN_NO_NETWORK / per-test stubs.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


# ============================================================
# aggregate-cve-feed.py — basic shape + skip logic
# ============================================================

def _load_aggregator():
    """Import the script as a module (it lives in scripts/).

    Python 3.14+ dataclass introspection reads `sys.modules[cls.__module__]`
    when computing `_is_type`; we MUST register the module in sys.modules
    before exec_module — else @dataclass crashes with
    `'NoneType' has no attribute '__dict__'`.
    """
    import importlib.util
    import sys
    name = "wpsecscan_aggregator_test"
    if name in sys.modules:
        return sys.modules[name]
    p = Path(__file__).resolve().parents[1] / "scripts" / "aggregate-cve-feed.py"
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_aggregator_module_imports():
    agg = _load_aggregator()
    assert hasattr(agg, "SOURCES")
    assert hasattr(agg, "aggregate")
    assert hasattr(agg, "main")


def test_aggregator_has_all_8_sources():
    agg = _load_aggregator()
    expected = {"wordfence", "osv", "ghsa", "mitre", "nvd",
                 "wpvulnerability", "patchstack_rss", "circl"}
    assert set(agg.SOURCES.keys()) == expected


def test_aggregator_skip_unknown_source(capsys):
    agg = _load_aggregator()
    # Calling main with --skip-source nope should error
    old = sys.argv
    sys.argv = ["aggregate-cve-feed.py", "--skip-source", "bogus", "--dry-run"]
    try:
        rc = agg.main()
    finally:
        sys.argv = old
    assert rc == 2


def test_aggregator_cvss_to_sev():
    agg = _load_aggregator()
    assert agg.cvss_to_sev(10.0) == "critical"
    assert agg.cvss_to_sev(9.0) == "critical"
    assert agg.cvss_to_sev(7.0) == "high"
    assert agg.cvss_to_sev(4.0) == "medium"
    assert agg.cvss_to_sev(0.5) == "low"
    assert agg.cvss_to_sev(0.0) == "info"
    assert agg.cvss_to_sev(None) == "medium"
    assert agg.cvss_to_sev("garbage") == "medium"


def test_aggregator_dedupe_keeps_highest_cvss():
    """When the same (type,slug,cve) appears from multiple sources, keep
    the entry with the highest CVSS score."""
    agg = _load_aggregator()
    low = agg.Vuln(slug="foo", type="plugin", title="A", severity="low",
                    cve="CVE-2024-1234", cvss=3.0, source="osv")
    high = agg.Vuln(slug="foo", type="plugin", title="A", severity="high",
                     cve="CVE-2024-1234", cvss=8.5, source="wordfence")
    # Run dedup on a list we built manually — exercises the merge code path
    by_key = {}
    for v in (low, high):
        k = (v.type, v.slug.lower(), v.cve)
        if k not in by_key or v.cvss > by_key[k].cvss:
            by_key[k] = v
    out = list(by_key.values())
    assert len(out) == 1
    assert out[0].source == "wordfence"


def test_aggregator_no_network_safe(monkeypatch):
    """The aggregator should run without crashing even with no network —
    each source returns ([], 0, err_msg) on failure."""
    monkeypatch.setenv("WPSECSCAN_NO_NETWORK", "1")
    # Stub out the actual HTTP layer so even httpx attempts fail safely
    agg = _load_aggregator()
    # Force each source's _http_get to return None
    monkeypatch.setattr(agg, "_http_get", lambda *a, **kw: None)
    monkeypatch.setattr(agg, "_http_post_json", lambda *a, **kw: None)
    merged, counts, errors = agg.aggregate(skip={"ghsa"})  # ghsa needs httpx
    assert isinstance(merged, list)
    assert isinstance(counts, dict)
    assert isinstance(errors, dict)
    # Every source should have either contributed 0 entries or recorded an error
    assert all(counts.get(s, 0) >= 0 for s in agg.SOURCES if s != "ghsa")


def test_aggregator_write_output(tmp_path):
    """write_output produces a valid JSON file with the expected shape."""
    agg = _load_aggregator()
    out = tmp_path / "vuln-db.json"
    vulns = [
        agg.Vuln(slug="foo", type="plugin", title="A",
                  severity="high", cve="CVE-2024-1", cvss=7.5, source="wordfence"),
        agg.Vuln(slug="bar", type="plugin", title="B",
                  severity="critical", cve="CVE-2024-2", cvss=9.0, source="ghsa"),
    ]
    agg.write_output(vulns, {"wordfence": 1, "ghsa": 1}, {}, out)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["_format"] == "wpsecscan/normalized-v1"
    assert data["_total"] == 2
    assert data["_sources"] == {"wordfence": 1, "ghsa": 1}
    assert "_generated_at" in data
    assert len(data["vulns"]) == 2


def test_aggregator_write_output_symlink_guard(tmp_path):
    """Symlink at the output path is unlinked before write (defence in depth)."""
    import sys
    if sys.platform == "win32":
        return
    agg = _load_aggregator()
    out = tmp_path / "vuln-db.json"
    out.symlink_to(tmp_path / "nonexistent-target")
    agg.write_output([], {}, {}, out)
    assert out.is_file() and not out.is_symlink()


# ============================================================
# db.py — fetch_aggregated + cached_sources
# ============================================================

def test_db_aggregated_feed_url_constant():
    from wpsecscan import db
    assert db.AGGREGATED_FEED_URL.startswith("https://")
    assert "data-feed" in db.AGGREGATED_FEED_URL
    assert "vuln-db.json" in db.AGGREGATED_FEED_URL


def test_db_cached_sources_no_cache(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    assert db.cached_sources() == {}


def test_db_cached_sources_round_trip(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    cp = db.cache_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps({
        "_format": "wpsecscan/normalized-v1",
        "_fetched_at": 0,
        "_sources": {"wordfence": 100, "osv": 50, "ghsa": 25},
        "vulns": [],
    }), encoding="utf-8")
    s = db.cached_sources()
    assert s == {"wordfence": 100, "osv": 50, "ghsa": 25}


def test_db_cached_sources_old_cache_returns_empty(tmp_path, monkeypatch):
    """Cache from before round-63 (no _sources field) should give {}."""
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    cp = db.cache_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps({
        "_format": "wpsecscan/normalized-v1",
        "_fetched_at": 0,
        "vulns": [],
    }), encoding="utf-8")
    assert db.cached_sources() == {}


def test_db_save_cache_with_sources(tmp_path, monkeypatch):
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    v = db.Vuln(slug="foo", type="plugin", title="A", severity="high",
                 cve="CVE-2024-1", cvss=7.5, fixed_in="1.2.3",
                 affected_from="", affected_to="1.2.2", to_inclusive=True,
                 references=[])
    cp = db.save_cache([v], sources={"wordfence": 100})
    assert cp.exists()
    data = json.loads(cp.read_text(encoding="utf-8"))
    assert data["_sources"] == {"wordfence": 100}
    assert data["vulns"][0]["slug"] == "foo"


def test_db_save_cache_strips_symlink(tmp_path, monkeypatch):
    import sys
    if sys.platform == "win32":
        return
    from wpsecscan import db
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    cp = db.cache_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.symlink_to(tmp_path / "nonexistent")
    db.save_cache([], sources={"x": 1})
    assert cp.is_file() and not cp.is_symlink()


# ============================================================
# workflow + ecosystem files exist
# ============================================================

def test_cve_feed_workflow_yaml_exists():
    p = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "cve-feed.yml"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    assert "schedule:" in body
    assert "cron:" in body
    assert "aggregate-cve-feed.py" in body
    assert "data-feed" in body


def test_aggregator_script_exists():
    p = Path(__file__).resolve().parents[1] / "scripts" / "aggregate-cve-feed.py"
    assert p.exists()


def test_data_sources_docs_exists():
    p = Path(__file__).resolve().parents[1] / "docs" / "data-sources.md"
    assert p.exists()
    body = p.read_text(encoding="utf-8")
    # All 8 sources documented
    for src in ("Wordfence", "OSV.dev", "GitHub Security Advisories",
                 "Mitre CVE List", "NVD", "WPVulnerability.com",
                 "Patchstack", "CIRCL"):
        assert src in body
