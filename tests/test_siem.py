"""Wave 3 — unit tests for wpsecscan/siem.py.

Covers the pure helpers (_build_events, _redact) and stub-out tests for
the four forwarders so we exercise the success/failure code paths
without needing real Splunk/Datadog/Loki/Logstash endpoints.
"""
from unittest.mock import patch, MagicMock

import httpx
import pytest

from wpsecscan import siem
from wpsecscan.models import CheckResult, Finding, ScanReport


@pytest.fixture
def sample_report():
    return ScanReport(
        target="https://example.com",
        scanned_at="2026-05-27T00:00:00",
        duration_ms=12345,
        results=[
            CheckResult(
                check_id="headers", check_name="HTTP security headers",
                findings=[
                    Finding(severity="high", title="Missing CSP",
                            evidence="No Content-Security-Policy header",
                            remediation="Add CSP", url="https://example.com/"),
                    Finding(severity="medium", title="X-Frame-Options",
                            evidence="missing", remediation="set to DENY"),
                ],
            ),
            CheckResult(
                check_id="tls", check_name="TLS audit",
                findings=[Finding(severity="info", title="TLS 1.3 OK",
                                   evidence="ok")],
            ),
        ],
    )


def test_build_events_flattens_findings(sample_report):
    events = siem._build_events(sample_report, source="test-src")
    assert len(events) == 3
    assert {e["severity"] for e in events} == {"high", "medium", "info"}
    assert all(e["target"] == "https://example.com" for e in events)
    assert all(e["source"] == "test-src" for e in events)
    assert all(e["scanner"] == "wpsecscan" for e in events)


def test_build_events_empty_report():
    rep = ScanReport(target="https://x", scanned_at="t", duration_ms=0, results=[])
    assert siem._build_events(rep, "x") == []


def test_redact_long_token():
    """Token-shaped substrings (>=24 chars base64/hex) get masked."""
    msg = "auth failed: token=abcdef1234567890abcdef1234567890ABC bad"
    redacted = siem._redact(msg)
    assert "[redacted-token]" in redacted
    assert "abcdef1234567890abcdef1234567890ABC" not in redacted


def test_redact_leaves_short_strings_alone():
    """English error text stays readable."""
    msg = "splunk HEC 401: invalid token"
    assert siem._redact(msg) == msg  # nothing token-shaped


def test_redact_jwt_like():
    """A JWT-shaped string is masked."""
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MTIzIn0.aBcDeFgHiJkLmNoPqRsT"
    msg = f"datadog 401: Bearer {jwt} expired"
    assert "[redacted-token]" in siem._redact(msg)


def test_post_splunk_empty_no_send(sample_report):
    rep = ScanReport(target="https://x", scanned_at="t", duration_ms=0, results=[])
    sent, msg = siem.post_splunk_hec(rep, "https://splunk", "tk")
    assert sent == 0
    assert "no findings" in msg


def test_post_splunk_success(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=200, text="ok")
        mc.return_value = client
        sent, msg = siem.post_splunk_hec(sample_report, "https://splunk", "tk")
    assert sent == 3
    assert "splunk HEC accepted" in msg


def test_post_splunk_4xx(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=401, text="bad token tk123")
        mc.return_value = client
        sent, msg = siem.post_splunk_hec(sample_report, "https://splunk", "tk")
    assert sent == 0
    assert "401" in msg


def test_post_splunk_network_error(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.side_effect = httpx.RequestError("connection refused")
        mc.return_value = client
        sent, msg = siem.post_splunk_hec(sample_report, "https://splunk", "tk")
    assert sent == 0
    assert "splunk HEC error" in msg


def test_post_datadog_success(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=202, text="")
        mc.return_value = client
        sent, msg = siem.post_datadog_logs(sample_report, "ddkey")
    assert sent == 3
    assert "datadog accepted" in msg


def test_post_loki_groups_streams(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=204, text="")
        mc.return_value = client
        sent, msg = siem.post_loki(sample_report, "https://loki/push")
    assert sent == 3
    # 3 distinct (job, target, sev, check_id) streams expected
    assert "across 3 stream" in msg


def test_post_beats_success(sample_report):
    with patch.object(siem.httpx, "Client") as mc:
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = MagicMock(status_code=200, text="")
        mc.return_value = client
        sent, msg = siem.post_beats(sample_report, "http://logstash:8080")
    assert sent == 3
    assert "logstash accepted" in msg


def test_forward_all_no_config_returns_empty(sample_report):
    """No env vars + no args = no forwarders fire."""
    args = MagicMock(siem_splunk=None, siem_splunk_token=None,
                      siem_datadog=None, siem_loki=None, siem_beats=None)
    with patch.dict("os.environ", {}, clear=False):
        # Strip the env keys forward_all reads
        import os
        for k in ("WPSECSCAN_SPLUNK_HEC", "WPSECSCAN_DATADOG_API_KEY",
                   "WPSECSCAN_LOKI_URL", "WPSECSCAN_BEATS_URL"):
            os.environ.pop(k, None)
        msgs = siem.forward_all(sample_report, args)
    assert msgs == []
