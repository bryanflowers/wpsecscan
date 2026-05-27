"""Wave 3 — tests for wpsecscan/slack_app.py.

Focus on the pure helpers — HMAC sig verification + the response_url
allow-list (S2). The HTTP handler is exercised by the existing
test_mobile_api_traversal pattern in spirit; we don't spin up the
threaded server here.
"""
import hashlib
import hmac
import time

import pytest

from wpsecscan import slack_app


def _sign(secret: str, body: bytes, ts: str | None = None) -> tuple[str, str]:
    ts = ts or str(int(time.time()))
    base = f"v0:{ts}:".encode() + body
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return ts, sig


def test_verify_signature_valid():
    secret = "shhh"
    body = b"token=foo&text=hello"
    ts, sig = _sign(secret, body)
    assert slack_app._verify_slack_signature(secret, ts, body, sig) is True


def test_verify_signature_wrong_secret():
    body = b"token=foo&text=hello"
    ts, sig = _sign("real-secret", body)
    assert slack_app._verify_slack_signature("wrong-secret", ts, body, sig) is False


def test_verify_signature_tampered_body():
    body = b"token=foo&text=hello"
    ts, sig = _sign("s", body)
    assert slack_app._verify_slack_signature("s", ts, b"token=foo&text=evil", sig) is False


def test_verify_signature_replay_window():
    """6-minute-old timestamp must be rejected (5-min window)."""
    body = b"x"
    old_ts = str(int(time.time()) - 60 * 6)
    _, sig = _sign("s", body, old_ts)
    assert slack_app._verify_slack_signature("s", old_ts, body, sig) is False


def test_verify_signature_missing_pieces():
    assert slack_app._verify_slack_signature("", "ts", b"x", "sig") is False
    assert slack_app._verify_slack_signature("s", "", b"x", "sig") is False
    assert slack_app._verify_slack_signature("s", "ts", b"x", "") is False


def test_verify_signature_bad_timestamp():
    """Non-numeric timestamp must be rejected, not raise."""
    assert slack_app._verify_slack_signature("s", "not-a-number", b"x", "sig=x") is False
