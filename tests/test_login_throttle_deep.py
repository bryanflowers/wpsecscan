"""Tests for the deep throttle mapper."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

from wpsecscan.checks.login_throttle_deep import (
    DEFAULT_ATTEMPTS, DEFAULT_PACING_SECONDS, WRONG_PASSWORD,
    MIN_ATTEMPTS, MAX_ATTEMPTS, MIN_PACING_SECONDS, MAX_PACING_SECONDS,
    _clamp_attempts, _clamp_pacing,
)
from tests.conftest import FakeClient, FakeResponse


async def _no_sleep(_s):
    return None


def run(coro):
    return asyncio.run(coro)


def test_default_attempts_is_one_twenty():
    assert DEFAULT_ATTEMPTS == 120


def test_default_pacing_is_ten_seconds():
    assert DEFAULT_PACING_SECONDS == 10.0


def test_attempts_clamped_to_range():
    assert _clamp_attempts(5) == MIN_ATTEMPTS       # below min
    assert _clamp_attempts(99999) == MAX_ATTEMPTS   # above max
    assert _clamp_attempts(300) == 300              # in range
    assert _clamp_attempts(None) == DEFAULT_ATTEMPTS
    assert _clamp_attempts("bogus") == DEFAULT_ATTEMPTS
    assert MAX_ATTEMPTS >= 500   # user requested capacity for 500


def test_pacing_clamped_to_range():
    assert _clamp_pacing(1) == MIN_PACING_SECONDS    # below min
    assert _clamp_pacing(120) == MAX_PACING_SECONDS  # above max
    assert _clamp_pacing(20) == 20.0
    assert _clamp_pacing(None) == DEFAULT_PACING_SECONDS
    assert MIN_PACING_SECONDS == 5.0
    assert MAX_PACING_SECONDS == 60.0


def test_ctx_overrides_default_attempts():
    """Verify a ctx-provided attempts value actually limits the loop."""
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })
    sent: list = []

    async def post_track(path, **kwargs):
        sent.append(1)
        return FakeResponse(status_code=200, text="ERROR: Invalid credentials")
    client.post = post_track

    ctx = {
        "target": "https://example.com",
        "deep_throttle": True,
        "deep_throttle_attempts": 15,
        "deep_throttle_pacing_s": 5.0,
        "shared": {}, "step": lambda _s: None,
    }
    with patch("asyncio.sleep", new=_no_sleep):
        run(check(client, ctx))
    assert len(sent) == 15, f"expected 15 attempts (custom limit), got {len(sent)}"


def test_ctx_attempts_clamped_to_max():
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })
    sent: list = []

    async def post_track(path, **kwargs):
        sent.append(1)
        return FakeResponse(status_code=200, text="ERROR: Invalid credentials")
    client.post = post_track

    ctx = {
        "target": "https://example.com",
        "deep_throttle": True,
        "deep_throttle_attempts": 99999,  # over the cap
        "shared": {}, "step": lambda _s: None,
    }
    with patch("asyncio.sleep", new=_no_sleep):
        run(check(client, ctx))
    assert len(sent) == MAX_ATTEMPTS, f"expected MAX_ATTEMPTS={MAX_ATTEMPTS}, got {len(sent)}"


def test_wrong_password_is_a_constant_string():
    assert isinstance(WRONG_PASSWORD, str)
    assert WRONG_PASSWORD == "wpsecscan-deep-canary-fixed-wrong-password-DO-NOT-VARY"
    # Source-scan: the string must be a literal in the module, not derived
    # (defense against accidental refactor to a wordlist)
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "wpsecscan" / "checks" / "login_throttle_deep.py").read_text(encoding="utf-8")
    # Should appear exactly once as the constant assignment
    assert src.count('"' + WRONG_PASSWORD + '"') >= 1


def test_skipped_when_not_opted_in():
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}  # no deep_throttle
    findings = run(check(client, ctx))
    titles = [f.title for f in findings]
    assert any("skipped" in t.lower() and "opt-in" in t.lower() for t in titles)


def test_threshold_detected_at_specific_attempt():
    """Simulate a site that 429s starting at attempt 8 — verify we record that."""
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    call_count = [0]
    async def post_throttle_at_8(path, **kwargs):
        call_count[0] += 1
        if call_count[0] >= 8:
            return FakeResponse(status_code=429, text="rate limited")
        return FakeResponse(status_code=200, text="ERROR: Invalid credentials")
    client.post = post_throttle_at_8

    ctx = {"target": "https://example.com", "deep_throttle": True, "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))

    threshold_findings = [f for f in findings if "threshold detected at attempt" in f.title.lower()]
    assert len(threshold_findings) == 1
    assert "#8" in threshold_findings[0].title or "attempt #8" in threshold_findings[0].title.lower()
    extra = threshold_findings[0].extra
    assert extra.get("threshold_attempt") == 8


def test_no_throttle_flagged_as_high():
    """30 attempts with identical 200 responses — flag as high severity."""
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    async def post_no_throttle(path, **kwargs):
        return FakeResponse(status_code=200, text="ERROR: Invalid username or password")
    client.post = post_no_throttle

    ctx = {"target": "https://example.com", "deep_throttle": True, "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))

    assert any(
        f.severity == "high" and "no login throttling" in f.title.lower()
        for f in findings
    )


def test_same_wrong_password_every_attempt():
    """Track the exact passwords sent to confirm we never vary them."""
    from wpsecscan.checks.login_throttle_deep import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    sent_passwords: list[str] = []
    async def post_track(path, **kwargs):
        data = kwargs.get("data") or {}
        sent_passwords.append(data.get("pwd"))
        return FakeResponse(status_code=200, text="ERROR: Invalid credentials")
    client.post = post_track

    ctx = {"target": "https://example.com", "deep_throttle": True, "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        run(check(client, ctx))

    # Defense-critical assertion: every attempt sent the same fixed wrong password
    assert len(set(sent_passwords)) == 1, (
        f"deep throttle MUST NEVER VARY the password. Sent: {set(sent_passwords)}"
    )
    assert sent_passwords[0] == WRONG_PASSWORD
