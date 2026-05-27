"""Regression tests for v2.7.1 S2 — GraphQL injection in
push_linear_triage + push_monday.

The pre-fix code built mutations via f-string with `chr(34)→chr(39)`
substitution. A title containing `\\` + `"` survives the substitution
and breaks out of the GraphQL string literal.
"""
from unittest.mock import patch, MagicMock

import httpx
import pytest

from wpsecscan import integrations_v27
from wpsecscan.models import CheckResult, Finding, ScanReport


def _make_report(title: str, severity: str = "high"):
    return ScanReport(
        target="https://example.com", scanned_at="2026-05-27T00:00:00",
        duration_ms=0,
        results=[CheckResult(check_id="t", check_name="t",
                              findings=[Finding(severity=severity, title=title,
                                                  evidence="payload")])],
    )


def _capture_json(mock_client):
    """Pull the JSON body of the LAST post() call on the mocked client."""
    instance = mock_client.return_value
    instance.__enter__.return_value = instance
    instance.post.return_value = MagicMock(status_code=200, text="ok")
    return instance


def test_linear_uses_variables_not_fstring(monkeypatch):
    monkeypatch.setenv("LINEAR_API_KEY", "test")
    monkeypatch.setenv("LINEAR_TRIAGE_TEAM_ID", "team-x")
    # Title contains a backslash + double-quote that would break the
    # pre-fix f-string + chr(34)→chr(39) substitution and inject a
    # second mutation. The parameterised query must NOT echo this text.
    rep = _make_report('Evil " title with \\\') + "); mutation deleteAll {}')
    with patch.object(integrations_v27.httpx, "Client") as mc:
        instance = _capture_json(mc)
        ok, msg = integrations_v27.push_linear_triage(rep)
    # Confirm the call used variables, NOT a query containing the title literal
    args, kwargs = instance.post.call_args
    payload = kwargs.get("json", {})
    assert "variables" in payload, "linear push must use GraphQL variables"
    # The query string should be the static parameterised mutation
    assert "$input" in payload["query"], "linear query must use $input variable"
    # The title goes in variables.input.title, NOT in the query string
    assert payload["variables"]["input"]["title"].startswith("Evil")
    # Critically: the raw title must NOT appear in the query string itself
    assert "Evil" not in payload["query"]


def test_monday_uses_variables_not_fstring(monkeypatch):
    monkeypatch.setenv("MONDAY_TOKEN", "test")
    monkeypatch.setenv("MONDAY_BOARD_ID", "12345")
    rep = _make_report('Hostile " title \\\'); mutation deleteBoards')
    with patch.object(integrations_v27.httpx, "Client") as mc:
        instance = _capture_json(mc)
        ok, msg = integrations_v27.push_monday(rep)
    args, kwargs = instance.post.call_args
    payload = kwargs.get("json", {})
    assert "variables" in payload, "monday push must use GraphQL variables"
    assert "$name" in payload["query"], "monday query must use $name variable"
    assert payload["variables"]["name"].startswith("Hostile")
    assert "Hostile" not in payload["query"]


def test_monday_rejects_non_integer_board_id(monkeypatch):
    monkeypatch.setenv("MONDAY_TOKEN", "test")
    monkeypatch.setenv("MONDAY_BOARD_ID", "not-an-int")
    rep = _make_report("test")
    ok, msg = integrations_v27.push_monday(rep)
    assert ok is False
    assert "integer" in msg.lower()
