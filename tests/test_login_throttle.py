"""Tests for the login-throttling defense check."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

from wpsecscan.checks.login_throttle import ATTEMPTS
from tests.conftest import FakeClient, FakeResponse


async def _no_sleep(_s):
    return None


def run(coro):
    return asyncio.run(coro)


def test_attempts_capped_at_six():
    assert ATTEMPTS == 6


def test_throttle_detected_when_429():
    from wpsecscan.checks.login_throttle import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    call_count = [0]
    async def post_throttle(path, **kwargs):
        call_count[0] += 1
        if call_count[0] >= 3:
            return FakeResponse(status_code=429, text="rate limit")
        return FakeResponse(status_code=200, text="Login failed")
    client.post = post_throttle

    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))

    assert any("kicked in" in f.title.lower() and f.severity == "info" for f in findings)


def test_no_throttle_flagged_as_medium():
    from wpsecscan.checks.login_throttle import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    async def post_no_throttle(path, **kwargs):
        return FakeResponse(status_code=200, text="ERROR: Invalid credentials")
    client.post = post_no_throttle

    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))

    assert any("no login rate-limiting" in f.title.lower() and f.severity == "medium" for f in findings)
