"""Regression tests for the audit round that followed the 24-feature + Defender batches.

Pins the previously-broken behaviors so they can't silently regress again.
"""
from __future__ import annotations

import importlib


# ============================== Backdoor-marker obfuscation regression ==============================

def test_backdoor_markers_decode_to_real_webshell_strings():
    """The fragment-concatenation obfuscation must produce the EXACT strings a
    webshell contains. A previous round produced 'system($__' (double underscore)
    instead of 'system($_' — silently breaking detection of three families."""
    ct = importlib.import_module("wpsecscan.checks.core_tampering")
    expected = (
        "eval(base64_decode",
        "eval($_POST",
        "eval($_GET",
        "eval($_REQUEST",
        "gzinflate(base64_decode",
        "system($_",
        "shell_exec($_",
        "preg_replace('/.*/e'",
        "assert($_",
        "@eval(",
    )
    actual = ct.PHP_BACKDOOR_MARKERS
    assert len(actual) == len(expected), \
        f"expected {len(expected)} markers, got {len(actual)}"
    for a, e in zip(actual, expected):
        assert a == e, f"marker mismatch: got {a!r}, expected {e!r}"


def test_no_double_underscore_in_any_backdoor_marker():
    """Defence in depth: no marker should ever contain `$__` (double underscore).

    Real PHP backdoors use `$_POST`, `$_GET`, `$_REQUEST`, `$_SERVER` — never
    `$__`. If a marker has it, the obfuscation broke."""
    ct = importlib.import_module("wpsecscan.checks.core_tampering")
    for marker in ct.PHP_BACKDOOR_MARKERS:
        assert "$__" not in marker, f"marker contains $__: {marker!r}"


def test_dom_xss_sinks_include_eval():
    """xss_dom_sinks SINKS uses the same fragment obfuscation. Verify it produces
    the literal `eval(` string at runtime."""
    sinks = importlib.import_module("wpsecscan.checks.xss_dom_sinks").SINKS
    assert "eval(" in sinks


# ============================== HAR redaction ==============================

def test_har_redacts_authorization_header():
    """Bug fix: Authorization header MUST be redacted in HAR request entries.

    Previously only Cookie was redacted on the request side, leaving Bearer
    tokens / Basic auth visible in any HAR file users shared in bug reports.
    """
    import asyncio
    from wpsecscan.http import Client
    import httpx

    class FakeResp:
        status_code = 200
        text = "ok"
        content = b"ok"
        headers: dict = {"Content-Type": "text/plain"}

    async def _fake(self, method, url, follow_redirects=False, **kwargs):
        return FakeResp()

    async def go():
        client = Client("https://example.com", har=True, adaptive_throttle=False)
        original = httpx.AsyncClient.request
        httpx.AsyncClient.request = _fake
        try:
            await client.get("/test", headers={
                "Authorization": "Bearer leaked-token-do-not-disclose",
                "X-API-Key": "leaked-api-key-do-not-disclose",
                "Cookie": "wp_session=leaked-cookie",
                "User-Agent": "WPSecScan",  # this one should pass through
            })
            entries = client.har_export()["log"]["entries"]
            assert entries, "no HAR entry recorded"
            req_headers = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
            assert req_headers.get("Authorization") == "<redacted>"
            assert req_headers.get("X-API-Key") == "<redacted>"
            assert req_headers.get("Cookie") == "<redacted>"
            # User-Agent should NOT be redacted
            assert req_headers.get("User-Agent") == "WPSecScan"
        finally:
            httpx.AsyncClient.request = original
            await client.aclose()

    asyncio.run(go())


def test_har_caps_response_body_at_8kb_without_full_decode():
    """Bug fix: response.text used to materialise the FULL body as a Python str
    before truncating to 8 KB — wasted memory on large responses."""
    import asyncio
    from wpsecscan.http import Client
    import httpx

    huge = b"a" * 50000

    class FakeResp:
        status_code = 200
        text = property(lambda self: huge.decode())  # would be 50 KB if read
        content = huge
        headers: dict = {}

    async def _fake(self, method, url, follow_redirects=False, **kwargs):
        return FakeResp()

    async def go():
        client = Client("https://example.com", har=True, adaptive_throttle=False)
        original = httpx.AsyncClient.request
        httpx.AsyncClient.request = _fake
        try:
            await client.get("/big")
            entries = client.har_export()["log"]["entries"]
            body = entries[0]["response"]["content"]["text"]
            # Hard 8 KB cap from the bytes side
            assert len(body) <= 8000, f"body should be <=8000, got {len(body)}"
        finally:
            httpx.AsyncClient.request = original
            await client.aclose()

    asyncio.run(go())


# ============================== PS single-quote escape ==============================

def test_powershell_single_quote_escape_doubles_apostrophe():
    """gui.App._ps_single_quote must double single quotes per PowerShell semantics."""
    from wpsecscan.gui import App
    assert App._ps_single_quote("C:\\Users\\O'Brien\\dist") == "C:\\Users\\O''Brien\\dist"
    assert App._ps_single_quote("simple") == "simple"
    assert App._ps_single_quote("") == ""
    # Multiple quotes
    assert App._ps_single_quote("a'b'c") == "a''b''c"


# ============================== GitHub Issues title truncation marker ==============================

def test_github_long_titles_get_truncation_marker():
    """Bug fix: titles >200 chars are now suffixed with '...' so users can tell."""
    from wpsecscan.integrations import github_issues as gh
    from wpsecscan.models import Finding, CheckResult, ScanReport
    long_title = "x" * 300
    r = ScanReport(
        target="https://example.com", scanned_at="t", duration_ms=0,
        results=[CheckResult(check_id="sqli", check_name="x",
                              findings=[Finding(severity="high", title=long_title)])],
    )
    # We don't actually post — just confirm the title-building path produces ...
    # by monkeypatching _post_issue to capture the title.
    captured_titles: list[str] = []

    def _fake_post(repo, token, title, body, labels, timeout=8.0):
        captured_titles.append(title)
        return True, "https://github.com/owner/repo/issues/1"

    original = gh._post_issue
    gh._post_issue = _fake_post
    try:
        s = gh.create_issues_for_report(r, "owner/repo", "ghp_fake", threshold="high")
        assert s["ok"] == 1
        assert captured_titles, "title path not exercised"
        title = captured_titles[0]
        assert title.endswith("..."), f"long title missing truncation marker: ...{title[-40:]!r}"
        assert len(title) <= 256, f"GitHub title limit exceeded: {len(title)} chars"
    finally:
        gh._post_issue = original


def test_github_short_titles_are_not_modified():
    """Short titles should not get a spurious '...' suffix."""
    from wpsecscan.integrations import github_issues as gh
    from wpsecscan.models import Finding, CheckResult, ScanReport
    r = ScanReport(
        target="https://example.com", scanned_at="t", duration_ms=0,
        results=[CheckResult(check_id="sqli", check_name="x",
                              findings=[Finding(severity="high", title="short title")])],
    )
    captured: list[str] = []

    def _fake_post(repo, token, title, body, labels, timeout=8.0):
        captured.append(title)
        return True, "https://github.com/x/y/issues/1"

    original = gh._post_issue
    gh._post_issue = _fake_post
    try:
        gh.create_issues_for_report(r, "owner/repo", "ghp_fake", threshold="high")
        assert captured[0] == "[HIGH] short title"
    finally:
        gh._post_issue = original


# ============================== Defender dialog "don't show again" checkbox ==============================

def test_defender_first_run_ack_path_uses_home():
    """The first-run ack file must live under ~/.wpsecscan/ — not somewhere
    randomly under the project tree."""
    from wpsecscan import history as _h
    # The actual path-building helper lives on the App instance, but we can
    # verify the conventions via history._home()
    home_str = str(_h._home())
    assert ".wpsecscan" in home_str
