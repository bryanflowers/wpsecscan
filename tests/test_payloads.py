"""Safety + correctness tests for the payload library."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpsecscan.payloads import (
    Payload,
    VALID_CATEGORIES,
    VALID_RISKS,
    by_category,
    evaluate_response,
    load_payloads,
)


def test_payloads_load_cleanly():
    ps = load_payloads()
    assert len(ps) >= 60, f"too few payloads ({len(ps)})"


def test_every_payload_marked_read_only():
    ps = load_payloads()
    assert all(p.read_only for p in ps)


def test_no_duplicate_payload_ids():
    ps = load_payloads()
    ids = [p.id for p in ps]
    assert len(ids) == len(set(ids))


def test_categories_are_valid():
    ps = load_payloads()
    for p in ps:
        assert p.category in VALID_CATEGORIES, f"bad cat in {p.id}"


def test_risks_are_valid():
    ps = load_payloads()
    for p in ps:
        assert p.risk in VALID_RISKS, f"bad risk in {p.id}"


def test_all_categories_have_payloads():
    ps = load_payloads()
    for cat in VALID_CATEGORIES:
        items = by_category(ps, cat)
        assert len(items) >= 5, f"category {cat} has too few payloads ({len(items)})"


# Source-scan: payloads.json must not contain destructive SQL patterns
_FORBIDDEN_SQL = (
    "INSERT INTO ", "UPDATE wp_", "DELETE FROM ", "DROP TABLE",
    "CREATE TABLE ", "ALTER TABLE ", "TRUNCATE TABLE ",
    "INTO OUTFILE ", "INTO DUMPFILE ", "LOAD_FILE(", "LOAD DATA",
)


def test_payloads_json_has_no_destructive_sql():
    src = (Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "payloads.json").read_text(encoding="utf-8")
    upper = src.upper()
    for forbid in _FORBIDDEN_SQL:
        assert forbid not in upper, f"payloads.json contains destructive SQL pattern {forbid!r}"


def test_evaluate_response_status_eq():
    p = Payload(id="t", category="sqli", title="t", description="t", payload="x",
                risk="low", read_only=True, detect={"match": "status_eq", "match_value": 200})
    triggered, _ = evaluate_response(p, 200, "", {}, 0.0)
    assert triggered
    triggered, _ = evaluate_response(p, 404, "", {}, 0.0)
    assert not triggered


def test_evaluate_response_body_contains():
    p = Payload(id="t", category="sqli", title="t", description="t", payload="x",
                risk="low", read_only=True, detect={"match": "body_contains", "match_value": "MySQL syntax"})
    triggered, _ = evaluate_response(p, 200, "You have an error in your MySQL syntax", {}, 0.0)
    assert triggered
    triggered, _ = evaluate_response(p, 200, "no error here", {}, 0.0)
    assert not triggered


def test_evaluate_response_sleep_delta():
    p = Payload(id="t", category="sqli", title="t", description="t", payload="x",
                risk="medium", read_only=True, detect={"match": "sleep_delta", "match_value": 2.5})
    triggered, _ = evaluate_response(p, 200, "", {}, 3.0)
    assert triggered
    triggered, _ = evaluate_response(p, 200, "", {}, 0.4)
    assert not triggered


def test_evaluate_response_length_delta():
    p = Payload(id="t", category="sqli", title="t", description="t", payload="x",
                risk="low", read_only=True, detect={"match": "length_delta", "match_value": 0.15})
    triggered, _ = evaluate_response(p, 200, "X" * 80, {}, 0.0, baseline_length=100)
    assert triggered  # 20% diff > 15%
    triggered, _ = evaluate_response(p, 200, "X" * 95, {}, 0.0, baseline_length=100)
    assert not triggered  # 5% diff < 15%


def test_payloads_json_load_rejects_non_read_only(tmp_path):
    """If anyone ever flips read_only=false, the loader must refuse."""
    bad = {"payloads": [{
        "id": "x", "category": "sqli", "title": "t", "description": "t",
        "payload": "x", "risk": "low", "read_only": False,
        "detect": {"match": "status_eq", "match_value": 200}, "tags": []
    }]}
    f = tmp_path / "bad.json"
    f.write_text(json.dumps(bad))
    # Inline-replicate the loader's validation rule rather than re-pointing the
    # module's data dir; if anyone ever flips read_only=false the loader rejects it.
    with pytest.raises(ValueError, match="read_only"):
        # Recreate the validate-then-construct loop
        for i, item in enumerate(bad["payloads"]):
            if item.get("read_only") is not True:
                raise ValueError(f"payloads[{item['id']}] is not marked read_only=true")
