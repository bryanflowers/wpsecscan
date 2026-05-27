"""Wave 3 — unit tests for wpsecscan/gh_check_run.py."""
from unittest.mock import patch, MagicMock

import pytest

from wpsecscan import gh_check_run
from wpsecscan.models import CheckResult, Finding, ScanReport


def _make_report(*findings):
    return ScanReport(
        target="https://example.com",
        scanned_at="2026-05-27T00:00:00",
        duration_ms=1234,
        results=[CheckResult(check_id="x", check_name="X", findings=list(findings))],
    )


def test_conclusion_success_when_no_findings_at_or_above_fail_on():
    rep = _make_report(Finding(severity="low", title="minor"))
    concl, title = gh_check_run._conclusion(rep, "high")
    assert concl == "success"
    assert "clean at >= high" in title


def test_conclusion_failure_when_threshold_hit():
    rep = _make_report(
        Finding(severity="high", title="bad"),
        Finding(severity="low", title="minor"),
    )
    concl, title = gh_check_run._conclusion(rep, "high")
    assert concl == "failure"
    assert "HIGH finding" in title


def test_conclusion_failure_when_above_threshold():
    rep = _make_report(Finding(severity="critical", title="catastrophe"))
    concl, title = gh_check_run._conclusion(rep, "high")
    assert concl == "failure"
    assert "CRITICAL" in title


def test_conclusion_neutral_when_fail_on_invalid():
    rep = _make_report(Finding(severity="critical", title="x"))
    concl, title = gh_check_run._conclusion(rep, "unknown-sev")
    assert concl == "neutral"


def test_conclusion_empty_report_with_fail_on():
    rep = _make_report()
    concl, _ = gh_check_run._conclusion(rep, "high")
    assert concl == "success"  # nothing >= high


def test_summary_md_includes_severity_table():
    rep = _make_report(
        Finding(severity="critical", title="c"),
        Finding(severity="high", title="h"),
        Finding(severity="high", title="h2"),
    )
    md = gh_check_run._summary_md(rep)
    assert "Risk score" in md
    assert "| Critical | 1 |" in md
    assert "| High     | 2 |" in md
    assert "https://example.com" in md


def test_post_check_run_no_token_raises():
    rep = _make_report()
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RuntimeError, match="GITHUB_TOKEN"):
            gh_check_run.post_check_run(rep, "owner", "repo", "abc123")


def test_post_check_run_success():
    rep = _make_report(Finding(severity="medium", title="med"))
    fake_resp = {"id": 1234, "html_url": "https://github.com/...",
                  "conclusion": "success"}
    with patch.object(gh_check_run.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(
            status_code=201, json=lambda: fake_resp, text="",
        )
        mc.return_value = client
        resp = gh_check_run.post_check_run(rep, "owner", "repo", "abc",
                                             token="ghp_test", fail_on="high")
    assert resp["id"] == 1234


def test_post_check_run_http_error_raises():
    rep = _make_report()
    with patch.object(gh_check_run.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=422, text="bad SHA")
        mc.return_value = client
        with pytest.raises(RuntimeError, match="422"):
            gh_check_run.post_check_run(rep, "owner", "repo", "abc",
                                          token="ghp_test")
