"""Risk score: weighted-deduction formula with per-tier caps."""
from __future__ import annotations

from wpsecscan.models import CheckResult, Finding, ScanReport
from wpsecscan.risk import compute_risk_score, risk_label, risk_tier


def _report(*findings: Finding) -> ScanReport:
    return ScanReport(
        target="https://example.com",
        scanned_at="2026-05-22T00:00:00Z",
        duration_ms=0,
        results=[CheckResult(check_id="t", check_name="t", findings=list(findings))],
    )


def _f(sev: str) -> Finding:
    return Finding(severity=sev, title=f"{sev} finding")


def test_clean_report_is_100():
    assert compute_risk_score(_report()) == 100


def test_info_findings_do_not_deduct():
    r = _report(_f("info"), _f("info"), _f("info"))
    assert compute_risk_score(r) == 100


def test_plan_example_one_high_two_medium_is_84():
    # Plan says: 1 high (-10) + 2 medium (-3*2 = -6) -> 100 - 16 = 84
    r = _report(_f("high"), _f("medium"), _f("medium"))
    assert compute_risk_score(r) == 84


def test_critical_capped_at_50():
    # 5 criticals would naively deduct 125; cap is 50.
    r = _report(*[_f("critical") for _ in range(5)])
    assert compute_risk_score(r) == 50


def test_high_capped_at_30():
    r = _report(*[_f("high") for _ in range(10)])
    assert compute_risk_score(r) == 70


def test_floor_at_zero():
    # All caps maxed: critical -50, high -30, medium -12, low -8 = -100 -> 0
    findings = (
        [_f("critical")] * 10
        + [_f("high")] * 10
        + [_f("medium")] * 10
        + [_f("low")] * 20
    )
    r = _report(*findings)
    assert compute_risk_score(r) == 0


def test_low_severity_caps_at_8():
    r = _report(*[_f("low") for _ in range(20)])
    assert compute_risk_score(r) == 92


def test_risk_tiers():
    assert risk_tier(100) == "green"
    assert risk_tier(90) == "green"
    assert risk_tier(89) == "yellow"
    assert risk_tier(70) == "yellow"
    assert risk_tier(69) == "orange"
    assert risk_tier(40) == "orange"
    assert risk_tier(39) == "red"
    assert risk_tier(0) == "red"


def test_risk_labels_are_distinct_strings():
    labels = {risk_label(s) for s in (95, 75, 50, 20)}
    assert len(labels) == 4


def test_scan_report_risk_score_property_matches():
    r = _report(_f("high"), _f("medium"))
    assert r.risk_score == compute_risk_score(r)


def test_to_dict_includes_risk_score():
    r = _report(_f("medium"))
    assert "risk_score" in r.to_dict()
    assert r.to_dict()["risk_score"] == 97
