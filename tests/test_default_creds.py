"""Safety tests for default-credentials probe."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

from wpsecscan.checks.default_creds import DEFAULT_CREDENTIALS
from tests.conftest import FakeClient, FakeResponse


async def _no_sleep(_s):  # async stub so asyncio.sleep can be patched
    return None


def run(coro):
    return asyncio.run(coro)


def test_default_creds_list_capped():
    assert len(DEFAULT_CREDENTIALS) <= 10, "default-creds must stay ≤10"


def test_default_creds_no_email_lookups():
    """No entry uses an email-shaped username — these are local accounts only."""
    for user, _ in DEFAULT_CREDENTIALS:
        assert "@" not in user, f"username {user!r} looks like an email"


def test_default_creds_aborts_on_429():
    """Throttling on attempt 1 should abort and emit info, not a failure cascade."""
    from wpsecscan.checks.default_creds import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(text='<form><input name="user_login"></form>'),
    })

    async def post_429(path, **kwargs):
        return FakeResponse(status_code=429, text="Too many requests")
    client.post = post_429

    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}

    with patch("asyncio.sleep", new=_no_sleep):
        findings = run(check(client, ctx))

    titles = [f.title for f in findings]
    assert any("aborted" in t.lower() or "throttling" in t.lower() for t in titles)


def test_default_creds_skips_if_login_unreachable():
    from wpsecscan.checks.default_creds import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(status_code=404),
    })
    ctx = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert any("skipped" in f.title.lower() for f in findings)


def test_default_creds_skipped_on_wordfence():
    """When Wordfence is fronting the site, do NOT attempt logins — its default
    lockout policy permanently bans the source IP after 5 failed attempts."""
    from wpsecscan.checks.default_creds import check
    client = FakeClient(responses={})  # should not be called
    ctx = {"target": "https://example.com", "shared": {"waf": ["Wordfence"]},
           "step": lambda _s: None}
    findings = run(check(client, ctx))
    assert len(findings) == 1
    assert "Wordfence" in findings[0].title
    assert "skipped" in findings[0].title.lower()


def test_default_creds_runs_on_wordfence_with_override():
    """--ignore-lockout-risk override bypasses the Wordfence skip."""
    from wpsecscan.checks.default_creds import check
    client = FakeClient(responses={
        "/wp-login.php": FakeResponse(status_code=404),  # unreachable triggers the next skip
    })
    ctx = {"target": "https://example.com",
           "shared": {"waf": ["Wordfence"]},
           "ignore_lockout_risk": True,
           "step": lambda _s: None}
    findings = run(check(client, ctx))
    # The override let us past the WAF gate; we land on the "login unreachable" skip
    assert any("not reachable" in f.title for f in findings)
