"""v2.8.3 Phase 3.4 — regression guards for the Phase 1 bug fixes.

Each test asserts the specific behavior the v2.8.3 fix restored:
- H1 cache_poisoning must NOT fire on `Cache-Control: public, no-store`
- H2 api_server _history_for must NOT match adjacent files
- H5 GUI _drain_queue must guard with winfo_exists (best-effort headless)
- M5 debug_leaks must NOT fire on bare 500 without PHP error markers
"""
from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx(target: str = "https://example.com") -> dict:
    return {"target": target, "shared": {}, "step": lambda _s: None}


# ===========================================================================
# H1 — cache_poisoning operator-precedence regression
# ===========================================================================
def test_h1_cache_poisoning_does_not_fire_on_public_no_store():
    """v2.8.3 H1: `public, no-store` must NOT be classified cacheable
    (the v2.8.2 expression had `and` binding tighter than `or` so the
    no-store guard only applied to the max-age sub-clause)."""
    from wpsecscan.checks.cache_poisoning import check
    canary_response = FakeResponse(
        status_code=200,
        text="<html><body>Reflected: WPSECSCAN_CANARY</body></html>",
        headers={"cache-control": "public, no-store", "age": "30"},
    )
    client = FakeClient(responses={"*": canary_response})
    findings = _run(check(client, _ctx()))
    cacheable_findings = [f for f in findings
                            if "cache" in (f.evidence or "").lower()
                            and "cacheable" in (f.evidence or "").lower()]
    # The expression's `no-store` guard must still kill the cacheable
    # classification even when `public` is in the header.
    assert all("public, no-store" not in (f.evidence or "") or
                "not cacheable" in (f.evidence or "").lower()
                for f in cacheable_findings), \
        f"H1 regression — public+no-store flagged cacheable: {[f.evidence for f in cacheable_findings]}"


def test_h1_cache_poisoning_source_uses_parenthesised_expression():
    """v2.8.3 H1: verify the source-code fix is in place (a guard
    against accidental regression in a future edit)."""
    src = Path("wpsecscan/checks/cache_poisoning.py").read_text(encoding="utf-8")
    # The fix must include parenthesised disjunction.
    assert '("max-age" in cc)' in src or '(("public" in cc)' in src or \
        '("public" in cc) or ("s-maxage"' in src, \
        "H1 fix removed — expected parenthesised disjunction in is_cacheable"


# ===========================================================================
# H2 — api_server history glob escape
# ===========================================================================
def test_h2_api_server_history_glob_is_prefix_anchored():
    """v2.8.3 H2: verify the source fix uses glob.escape + `-*.json`
    suffix (prefix-anchored) rather than the v2.8.2 `*safe*.json` that
    matched adjacent files."""
    src = Path("wpsecscan/api_server.py").read_text(encoding="utf-8")
    assert "glob.escape" in src or "_glob.escape" in src, \
        "H2 fix removed — expected glob.escape() call in api_server.py"
    # Must NOT contain the buggy leading-wildcard pattern.
    assert 'f"*{safe}*' not in src, \
        "H2 regression — leading-wildcard glob restored in api_server.py"


# ===========================================================================
# H5 — GUI _drain_queue winfo_exists guard
# ===========================================================================
def test_h5_gui_drain_queue_has_winfo_exists_guard():
    """v2.8.3 H5: verify the source fix wraps the after() reschedule
    in a winfo_exists check."""
    src = Path("wpsecscan/gui.py").read_text(encoding="utf-8")
    # Find the _drain_queue function body.
    assert "winfo_exists()" in src, "H5 fix removed — no winfo_exists call in gui.py"
    # The specific pattern we want: winfo_exists guard around the
    # _drain_queue reschedule.
    drain_idx = src.find("def _drain_queue")
    if drain_idx == -1:
        pytest.skip("_drain_queue not found")
    body = src[drain_idx:drain_idx + 5000]
    assert "winfo_exists" in body, \
        "H5 regression — _drain_queue no longer guards the after() reschedule"


# ===========================================================================
# M5 — debug_leaks bare-500 false positive
# ===========================================================================
def test_m5_debug_leaks_skips_bare_500_without_markers():
    """v2.8.3 M5: a 500 without any PHP error markers must NOT fire."""
    from wpsecscan.checks.debug_leaks import check
    client = FakeClient(responses={
        "/?p[]=1": FakeResponse(status_code=500, text="Service Unavailable"),
        "/?p[]=1&_wpnonce[]=x": FakeResponse(status_code=500, text=""),
    })
    findings = _run(check(client, _ctx()))
    php_leak = [f for f in findings
                  if "PHP error" in (f.title or "")
                  or "stack trace" in (f.title or "")]
    assert not php_leak, \
        f"M5 regression — bare 500 emitted finding: {[f.title for f in php_leak]}"


# ===========================================================================
# C1 — PHP companion SHOW TABLES LIKE prepare()
# ===========================================================================
def test_c1_php_show_tables_uses_prepare():
    """v2.8.3 C1: all SHOW TABLES LIKE sites in the companion PHP plugin
    must use $wpdb->prepare() so the pattern is correct (sets the
    example for neighboring devs not to copy bare interpolation into
    user-tainted contexts)."""
    src = Path("wp-plugin/wpsecscan-companion/includes/rest.php").read_text(encoding="utf-8")
    # There should be NO unprepared `SHOW TABLES LIKE '{$var}'` left.
    import re as _re
    bad = _re.findall(r"SHOW TABLES LIKE '\{\$[a-zA-Z_]+\}'", src)
    assert not bad, f"C1 regression — found unprepared SHOW TABLES LIKE: {bad}"


# ===========================================================================
# Reporter atomic-write migration (H3/H4)
# ===========================================================================
def test_h3_h4_no_reporter_uses_bare_write_text():
    """v2.8.3 H3+H4: all reporter modules must go through
    _atomic_write_text rather than calling Path.write_text directly.
    The pre-fix bare-write_text was a torn-file risk on SIGTERM."""
    import re as _re
    reporters_dir = Path("wpsecscan/reporters")
    offenders: list[str] = []
    for p in reporters_dir.glob("*.py"):
        if p.name == "__init__.py":
            continue
        src = p.read_text(encoding="utf-8")
        # Strip comments before scanning so we don't false-positive
        # on docstrings or commented-out examples.
        stripped = _re.sub(r"#.*$", "", src, flags=_re.MULTILINE)
        if _re.search(r"\b[a-zA-Z_]\w*\.write_text\(", stripped):
            offenders.append(p.name)
    assert not offenders, \
        f"H3/H4 regression — reporters bypass _atomic_write_text: {offenders}"
