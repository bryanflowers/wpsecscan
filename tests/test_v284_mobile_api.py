"""v2.8.4 Phase 6.3 — mobile_api endpoint tests.

Exercises the new POST /api/scan + per-finding detail endpoint + the
CORS preflight do_OPTIONS handler. Uses a minimal mocked Handler
instance because spawning a real HTTPServer in tests is heavy.
"""
from __future__ import annotations

import json
import os
from io import BytesIO
from unittest.mock import patch, MagicMock

import pytest


class _FakeRequest:
    """Minimal stand-in for a socket; rfile is a BytesIO, wfile a BytesIO."""
    def __init__(self, body: bytes = b""):
        self.rfile = BytesIO(body)
        self.wfile = BytesIO()

    def makefile(self, *args, **kwargs):
        return self.rfile

    def close(self):
        pass


def _build_handler_class():
    """Get the Handler class from the live mobile_api module."""
    from wpsecscan import mobile_api as _ma
    # The handler class is defined inside mobile_api; find it by name.
    return _ma._Handler if hasattr(_ma, "_Handler") else _ma._H


def _build_handler(method: str, path: str, body: bytes = b"",
                   token: str | None = None,
                   extra_headers: dict | None = None):
    """Build a Handler instance bypassing the real HTTPServer init."""
    from wpsecscan import mobile_api as _ma
    # mobile_api defines an inner class; introspect to find it.
    handler_cls = None
    for _name, obj in vars(_ma).items():
        if isinstance(obj, type) and obj.__name__ in ("_Handler", "_H"):
            handler_cls = obj
            break
    if handler_cls is None:
        # Fallback: search bases of any class that has do_GET defined
        for _name, obj in vars(_ma).items():
            if isinstance(obj, type) and hasattr(obj, "do_GET"):
                handler_cls = obj
                break
    assert handler_cls is not None, "mobile_api handler class not found"

    # Build a handler without invoking BaseHTTPRequestHandler.__init__
    h = handler_cls.__new__(handler_cls)
    h.rfile = BytesIO(body)
    h.wfile = BytesIO()
    h.headers = {
        "Content-Length": str(len(body)),
        **({"X-WPSecScan-Token": token} if token else {}),
        **(extra_headers or {}),
    }
    h.path = path
    h.command = method
    h.request_version = "HTTP/1.1"
    h.responses_sent = []
    h.headers_sent = []
    h.end_headers_called = False

    def _send_response(code, message=None):
        h.responses_sent.append(code)

    def _send_header(key, value):
        h.headers_sent.append((key, value))

    def _end_headers():
        h.end_headers_called = True

    h.send_response = _send_response
    h.send_header = _send_header
    h.end_headers = _end_headers
    h.log_message = lambda *_a, **_k: None
    return h


# ===========================================================================
# H7 + P4 — CORS headers on /api/reports
# ===========================================================================
def test_h7_cors_headers_present_on_send_json(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "test-token")
    h = _build_handler("GET", "/api/reports", token="test-token")
    # Patch _list_recent_reports to return a fixture
    with patch("wpsecscan.mobile_api._list_recent_reports", return_value=[]):
        h.do_GET()
    hdr_keys = [k for k, _v in h.headers_sent]
    assert "Access-Control-Allow-Origin" in hdr_keys, \
        f"H7 regression — Allow-Origin header missing. Got: {hdr_keys}"
    assert "Access-Control-Allow-Headers" in hdr_keys
    assert "Access-Control-Allow-Methods" in hdr_keys


def test_p4_options_preflight_returns_204():
    h = _build_handler("OPTIONS", "/api/scan")
    h.do_OPTIONS()
    assert 204 in h.responses_sent, \
        f"P4 regression — OPTIONS should return 204; got {h.responses_sent}"


# ===========================================================================
# H7 — 404 has explicit Content-Length: 0
# ===========================================================================
def test_h7_404_has_content_length_zero(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "test-token")
    h = _build_handler("GET", "/api/nonexistent", token="test-token")
    h.do_GET()
    cl = next((v for k, v in h.headers_sent if k == "Content-Length"), None)
    assert cl == "0", f"H7 regression — 404 missing Content-Length:0. Headers: {h.headers_sent}"


# ===========================================================================
# P1 — POST /api/scan requires auth + validates target
# ===========================================================================
def test_p1_post_scan_requires_auth(monkeypatch):
    """No token → 401."""
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "real-token")
    body = json.dumps({"target": "https://example.com"}).encode()
    h = _build_handler("POST", "/api/scan", body=body, token="wrong-token")
    h.do_POST()
    assert 401 in h.responses_sent, \
        f"P1 regression — wrong token should return 401; got {h.responses_sent}"


def test_p1_post_scan_rejects_invalid_target(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    body = json.dumps({"target": "not-a-url"}).encode()
    h = _build_handler("POST", "/api/scan", body=body, token="tok")
    h.do_POST()
    assert 400 in h.responses_sent, \
        f"P1 regression — invalid target should return 400; got {h.responses_sent}"


def test_p1_post_scan_rejects_oversized_body(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    body = b"x" * 20000
    h = _build_handler("POST", "/api/scan", body=body, token="tok",
                        extra_headers={"Content-Length": "20000"})
    h.do_POST()
    assert 413 in h.responses_sent, \
        f"P1 regression — oversized body should return 413; got {h.responses_sent}"


def test_p1_post_scan_accepts_valid_target_and_returns_queued(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    body = json.dumps({"target": "https://example.com"}).encode()
    h = _build_handler("POST", "/api/scan", body=body, token="tok")
    # Patch the background scan to avoid making a real HTTP request.
    with patch("threading.Thread") as mock_thread:
        mock_thread.return_value.start.return_value = None
        h.do_POST()
    assert 200 in h.responses_sent or not h.responses_sent, \
        f"P1 regression — valid POST should return 200; got {h.responses_sent}"
    written = h.wfile.getvalue().decode("utf-8")
    assert "queued" in written.lower() and "example.com" in written, \
        f"P1 regression — response body shape unexpected: {written[:200]}"


def test_p1_post_scan_404_on_wrong_path(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    h = _build_handler("POST", "/api/other", body=b"{}", token="tok")
    h.do_POST()
    assert 404 in h.responses_sent, \
        f"P1 regression — wrong POST path should return 404; got {h.responses_sent}"


# ===========================================================================
# P2 — per-finding detail endpoint
# ===========================================================================
def test_p2_per_finding_detail_path_traversal_guard(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    h = _build_handler("GET", "/api/report/..%2F..%2Fetc%2Fpasswd/findings/0",
                        token="tok")
    h.do_GET()
    # Should 404, not traverse paths
    assert 404 in h.responses_sent, \
        f"P2 regression — path-traversal should be blocked; got {h.responses_sent}"


def test_p2_per_finding_detail_rejects_invalid_idx(monkeypatch):
    monkeypatch.setenv("WPSECSCAN_MOBILE_TOKEN", "tok")
    h = _build_handler("GET", "/api/report/safe.json/findings/not-a-number",
                        token="tok")
    h.do_GET()
    assert 404 in h.responses_sent
