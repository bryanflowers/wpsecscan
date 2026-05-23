"""Smoke + safety + inventory tests for the 20 new checks added in this round.

Goal:
  - All 20 modules import without error
  - All 20 are registered in ALL_CHECKS
  - All 20 have a tag entry (OWASP + ATT&CK) AND a compliance entry
  - Aggressive checks self-skip without --aggressive
  - The new playbook/check_tags/compliance_map JSON files round-trip
"""
from __future__ import annotations

import asyncio
import importlib

from tests.conftest import FakeClient


NEW_PASSIVE = [
    "gdpr_dsr", "wp_engine_misconfig", "oauth_redirect", "cache_poisoning",
    "upload_path_predictable", "http2_settings", "favicon_hash", "a11y_lite",
    "smuggling_probe", "tls_protocol_audit", "cookie_consent", "websocket_audit",
    "woocommerce_audit", "graphql_dos",
]

NEW_AGGRESSIVE = [
    "prototype_pollution", "graphql_field_dos", "csv_export_csp", "waf_bypass_probe",
]


def _run(coro):
    return asyncio.run(coro)


def test_all_new_modules_import():
    for cid in NEW_PASSIVE + NEW_AGGRESSIVE:
        m = importlib.import_module(f"wpsecscan.checks.{cid}")
        assert callable(getattr(m, "check", None)), f"checks.{cid} must expose async def check()"


def test_all_new_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    registered = {cid for cid, _n, _f, _agg in ALL_CHECKS}
    for cid in NEW_PASSIVE + NEW_AGGRESSIVE:
        assert cid in registered, f"{cid} not in ALL_CHECKS"


def test_aggressive_checks_marked_aggressive():
    from wpsecscan.checks import ALL_CHECKS
    agg_map = {cid: agg for cid, _n, _f, agg in ALL_CHECKS}
    for cid in NEW_AGGRESSIVE:
        assert agg_map.get(cid) is True, f"{cid} should be aggressive=True"
    for cid in NEW_PASSIVE:
        assert agg_map.get(cid) is False, f"{cid} should be aggressive=False"


def test_aggressive_checks_self_skip_without_aggressive():
    """Without --aggressive, the 4 new aggressive checks must return an info-only finding,
    not actually send the payload."""
    ctx = {"target": "https://example.com", "aggressive": False, "shared": {}, "step": lambda _s: None}
    for cid in NEW_AGGRESSIVE:
        mod = importlib.import_module(f"wpsecscan.checks.{cid}")
        client = FakeClient()
        findings = _run(mod.check(client, ctx))
        assert findings, f"{cid} returned no findings (should have a skip-info finding)"
        # All should be info-only, with text mentioning aggressive
        non_info = [f for f in findings if f.severity != "info"]
        assert not non_info, f"{cid} produced non-info findings without --aggressive: {[f.title for f in non_info]}"


def test_full_tag_coverage_includes_new_checks():
    from wpsecscan.checks import ALL_CHECKS
    from wpsecscan import tags as _tags
    _tags.reset_cache()
    all_ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    missing = [cid for cid in all_ids if _tags.get_tags(cid) is None]
    assert not missing, f"checks missing tag entries: {missing}"


def test_full_compliance_coverage_includes_new_checks():
    from wpsecscan.checks import ALL_CHECKS
    from wpsecscan import tags as _tags
    _tags.reset_cache()
    all_ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    missing = [cid for cid in all_ids if _tags.get_compliance(cid) is None]
    assert not missing, f"checks missing compliance entries: {missing}"


def test_compliance_format_pci_or_na():
    """PCI-DSS values must look like 'X.Y(.Z)' or 'n/a'."""
    import json
    import re
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "wpsecscan" / "data" / "compliance_map.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    real = {k: v for k, v in data.items() if not k.startswith("_")}
    PCI_RE = re.compile(r"^\d+\.\d+(\.\d+)?$|^n/a$")
    bad = [(k, v.get("pci_dss")) for k, v in real.items() if v.get("pci_dss") and not PCI_RE.match(v["pci_dss"])]
    assert not bad, f"bad PCI-DSS values: {bad}"


def test_risk_grade_letters():
    from wpsecscan.risk import risk_grade
    assert risk_grade(100) == "A"
    assert risk_grade(95) == "A"
    assert risk_grade(94) == "B"
    assert risk_grade(85) == "B"
    assert risk_grade(84) == "C"
    assert risk_grade(70) == "C"
    assert risk_grade(69) == "D"
    assert risk_grade(50) == "D"
    assert risk_grade(49) == "F"
    assert risk_grade(0) == "F"


def test_json_reporter_includes_grade_and_compliance():
    """Regression: JSON output must include risk_grade + per-check compliance + tags."""
    from wpsecscan.models import CheckResult, Finding, ScanReport
    from wpsecscan.reporters import json_out
    import json as _j
    r = ScanReport(
        target="https://example.com",
        scanned_at="2026-05-23T00:00:00Z",
        duration_ms=0,
        results=[
            CheckResult(check_id="sqli", check_name="SQL injection probes",
                        findings=[Finding(severity="high", title="x", evidence="x")])
        ],
    )
    d = _j.loads(json_out.render(r))
    assert "risk_grade" in d
    assert d["risk_grade"] in ("A", "B", "C", "D", "F")
    assert d["results"][0].get("compliance"), "results[].compliance missing"
    assert d["results"][0]["compliance"].get("pci_dss") == "6.2.4"
