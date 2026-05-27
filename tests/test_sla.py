"""Wave 3 — unit tests for wpsecscan/sla.py."""
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from wpsecscan import sla


def _write_snap(path: Path, scanned_at: str, *findings):
    """Helper: write a snapshot JSON shaped like ScanReport.to_dict()."""
    data = {
        "target": "https://example.com",
        "scanned_at": scanned_at,
        "duration_ms": 0,
        "summary": {},
        "risk_score": 100,
        "results": [{
            "check_id": cid, "check_name": cid, "duration_ms": 0,
            "findings": [{"severity": sev, "title": title} for sev, title in fs],
        } for cid, fs in findings],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_build_ledger_first_seen(tmp_path):
    _write_snap(tmp_path / "01-2026-05-01.json", "2026-05-01T00:00:00",
                  ("headers", [("high", "Missing CSP")]))
    _write_snap(tmp_path / "02-2026-05-15.json", "2026-05-15T00:00:00",
                  ("headers", [("high", "Missing CSP")]))
    ledger = sla.build_ledger(tmp_path.glob("*.json"))
    entry = ledger[("headers", "Missing CSP")]
    assert entry["first_seen"] == "2026-05-01T00:00:00"
    assert entry["last_seen"] == "2026-05-15T00:00:00"
    assert entry["seen_count"] == 2
    assert entry["currently_open"] is True


def test_build_ledger_marks_closed_findings(tmp_path):
    _write_snap(tmp_path / "01-2026-05-01.json", "2026-05-01T00:00:00",
                  ("headers", [("high", "Missing CSP")]))
    _write_snap(tmp_path / "02-2026-05-15.json", "2026-05-15T00:00:00")  # empty
    ledger = sla.build_ledger(tmp_path.glob("*.json"))
    entry = ledger[("headers", "Missing CSP")]
    assert entry["currently_open"] is False


def test_days_open():
    entry = {"first_seen": "2026-05-01T00:00:00",
             "last_seen": "2026-05-10T00:00:00"}
    assert sla.days_open(entry) == 9


def test_days_open_missing_first():
    assert sla.days_open({}) is None


def test_sla_breached_open_critical():
    entry = {
        "currently_open": True,
        "last_severity": "critical",
        "first_seen": "2026-01-01T00:00:00",
        "last_seen": "2026-05-27T00:00:00",
    }
    assert sla.sla_breached(entry, {"critical": 7}) is True


def test_sla_not_breached_closed():
    entry = {
        "currently_open": False, "last_severity": "critical",
        "first_seen": "2026-01-01T00:00:00", "last_seen": "2026-05-27T00:00:00",
    }
    assert sla.sla_breached(entry, {"critical": 7}) is False


def test_sla_not_breached_within_window():
    entry = {
        "currently_open": True, "last_severity": "high",
        "first_seen": "2026-05-25T00:00:00", "last_seen": "2026-05-27T00:00:00",
    }
    assert sla.sla_breached(entry, {"high": 30}) is False


def test_sla_unknown_severity():
    entry = {"currently_open": True, "last_severity": "info",
             "first_seen": "2026-01-01T00:00:00",
             "last_seen": "2026-05-27T00:00:00"}
    assert sla.sla_breached(entry, {"critical": 7}) is False


def test_build_ledger_ignores_unreadable(tmp_path):
    """A corrupt snapshot doesn't crash the walk."""
    (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
    _write_snap(tmp_path / "ok.json", "2026-05-01T00:00:00",
                  ("x", [("high", "y")]))
    ledger = sla.build_ledger(tmp_path.glob("*.json"))
    assert ("x", "y") in ledger
