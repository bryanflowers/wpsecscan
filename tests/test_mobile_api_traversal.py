"""Regression test for B2: mobile-api `/api/report/{safe_host}` must
reject path-traversal payloads.

Before the fix the safe_host segment was URL-decoded and used directly
as a path component, so `/api/report/../../etc/passwd` could escape
~/.wpsecscan/reports/.
"""
import json
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer
from pathlib import Path

import pytest

from wpsecscan import mobile_api


@pytest.fixture
def server(monkeypatch, tmp_path):
    # Point the module at a sandbox home dir and seed one legit report.
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "test-token-1234567890abcdef")
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "example_com.json").write_text(
        json.dumps({"target": "https://example.com", "results": [],
                    "summary": {}, "risk_score": 100}),
        encoding="utf-8",
    )

    httpd = HTTPServer(("127.0.0.1", 0), mobile_api._Handler)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(port, path, *, token="test-token-1234567890abcdef"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                  headers={"X-WPSecScan-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def test_legit_path_works(server):
    code, body = _get(server, "/api/report/example_com")
    assert code == 200
    data = json.loads(body)
    assert data["target"] == "https://example.com"


def test_traversal_dotdot_rejected(server):
    """`../etc/passwd` and friends must 404, not escape reports/."""
    for evil in (
        "/api/report/../../etc/passwd",
        "/api/report/..%2F..%2Fetc%2Fpasswd",
        "/api/report/%2e%2e%2fpasswd",
        "/api/report/foo/../bar",
    ):
        code, _ = _get(server, evil)
        assert code == 404, f"expected 404 for {evil!r}, got {code}"


def test_absolute_path_rejected(server):
    """A literal absolute path must 404."""
    code, _ = _get(server, "/api/report/%2Fetc%2Fpasswd")
    assert code == 404


def test_unauthed_request_rejected(server):
    """No-token request must 401, even for legit paths."""
    req = urllib.request.Request(f"http://127.0.0.1:{server}/api/report/example_com")
    try:
        urllib.request.urlopen(req, timeout=2)
        raise AssertionError("expected 401")
    except urllib.error.HTTPError as e:
        assert e.code == 401
