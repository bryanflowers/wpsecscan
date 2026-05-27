"""Wave 3 — tests for wpsecscan/reporters/diff_agency.py."""
import json
from pathlib import Path

import pytest

from wpsecscan.reporters import diff_agency


def _dashboard_html(manifest: dict) -> str:
    """Synthesize the minimum dashboard HTML diff_agency reads from."""
    return (
        '<html><body><table>...</table>'
        f'<script type="application/json" id="wpsecscan-dashboard-data">'
        f'{json.dumps(manifest)}</script></body></html>'
    )


def test_extract_manifest_from_script(tmp_path):
    p = tmp_path / "d.html"
    p.write_text(_dashboard_html({"generated_at": "t", "totals": {},
                                    "sites": [{"target": "https://x",
                                                "risk_score": 90,
                                                "worst": "low",
                                                "summary": {}}]}),
                  encoding="utf-8")
    out = diff_agency._extract_manifest(p.read_text(encoding="utf-8"))
    assert out["sites"][0]["target"] == "https://x"


def test_extract_manifest_fallback_html_scrape(tmp_path):
    """Pre-v2.5.0 dashboards have no embedded manifest — table-scrape works."""
    html = (
        "<html><body><table>"
        "<tr><td>https://a.example</td><td>x</td><td>87/100</td></tr>"
        "<tr><td>https://b.example</td><td>x</td><td>42/100</td></tr>"
        "</table></body></html>"
    )
    out = diff_agency._extract_manifest(html)
    assert len(out["sites"]) == 2
    assert out["sites"][0]["target"] == "https://a.example"
    assert out["sites"][0]["risk_score"] == 87


def test_diff_added_removed_changed():
    old = {"sites": [
        {"target": "https://a", "risk_score": 90, "worst": "low", "summary": {}},
        {"target": "https://b", "risk_score": 70, "worst": "high", "summary": {}},
    ], "totals": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}}
    new = {"sites": [
        {"target": "https://a", "risk_score": 95, "worst": "low", "summary": {}},  # improved
        {"target": "https://c", "risk_score": 100, "worst": None, "summary": {}},  # new
    ], "totals": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}
    d = diff_agency.diff(old, new)
    assert [s["target"] for s in d["added"]] == ["https://c"]
    assert [s["target"] for s in d["removed"]] == ["https://b"]
    assert len(d["changed"]) == 1
    assert d["changed"][0]["target"] == "https://a"
    assert d["changed"][0]["delta"] == 5
    assert d["totals_delta"]["high"] == -1


def test_diff_empty_inputs():
    d = diff_agency.diff({"sites": [], "totals": {}}, {"sites": [], "totals": {}})
    assert d["added"] == []
    assert d["removed"] == []
    assert d["changed"] == []


def test_render_html_contains_section_headings():
    d = {
        "old_at": "t1", "new_at": "t2",
        "site_count_old": 1, "site_count_new": 1,
        "totals_delta": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "added": [],
        "removed": [],
        "changed": [{"target": "https://x", "old_score": 80, "new_score": 85,
                      "delta": 5, "old_worst": "high", "new_worst": "medium"}],
    }
    html = diff_agency.render_html(d)
    assert "Score / severity changes (1)" in html
    assert "https://x" in html
    assert "+5" in html


def test_write_round_trip(tmp_path):
    old = tmp_path / "old.html"
    new = tmp_path / "new.html"
    old.write_text(_dashboard_html({"generated_at": "t1", "totals": {},
                                      "sites": [{"target": "https://x",
                                                  "risk_score": 80,
                                                  "worst": "high",
                                                  "summary": {}}]}),
                    encoding="utf-8")
    new.write_text(_dashboard_html({"generated_at": "t2", "totals": {},
                                      "sites": [{"target": "https://x",
                                                  "risk_score": 90,
                                                  "worst": "medium",
                                                  "summary": {}}]}),
                    encoding="utf-8")
    out = tmp_path / "diff.html"
    d = diff_agency.write(old, new, out)
    assert out.exists()
    assert d["changed"][0]["delta"] == 10
