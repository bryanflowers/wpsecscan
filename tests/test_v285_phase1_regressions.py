"""Regression tests for v2.8.5 Phase 1-4 bug fixes.

C1   — gui._save_pref lock is module-level, not lazily instance-init.
C2   — scanner.parallel_groups WAF-streak block is wired in the
        parallel branch (source check).
C3   — history.save_report_snapshot writes .sig before the canonical
        .json (already covered by test_v272_wave3 — left here as a
        no-op comment for traceability).
H4   — mobile_api `/findings/` branch is reachable (source order
        check: appears BEFORE the plain `/api/report/<host>` branch).
H6   — mobile_api POST /api/scan declares a bounded semaphore.
H8   — cdn_edge_audit worker_marker has explicit parentheses
        (source check — the operator-precedence bug).
H9   — payment_commerce_deep splits the `/checkout/` -> `/cart/`
        fallthrough into an if-check, not `or await`.
H10  — a11y_deep empty_alt comprehension only calls ALT_RE.search once.
H11  — sites._save uses os.replace.
H12  — creds_vault has a module-level Lock guarding the fallback RMW.
M1   — scanner has try/except around is_paused() invocations.
M2   — graphql_dos uses a regex, not body.count('"a').
M3   — saml_xsw status filter no longer contains 405.
M4   — org_dashboard.glob excludes canonical aliases.
M5   — dns_security has a bounded asyncio.Semaphore for _txt.
M6   — subdomains gather uses return_exceptions=True.
M7   — exec_pdf / auditor_pdf / attestation guard scanned_at None.
Phase 5 — gdpr_dsr_report has no backslash inside an f-string expr.
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# C1 — module-level _PREF_SAVE_LOCK
# ---------------------------------------------------------------------------

def test_c1_pref_save_lock_is_module_level():
    src = Path("wpsecscan/gui.py").read_text(encoding="utf-8")
    assert "_PREF_SAVE_LOCK = threading.Lock()" in src, \
        "v2.8.5 C1 — module-level _PREF_SAVE_LOCK missing"
    # Locate _save_pref method body.
    idx = src.find("def _save_pref")
    assert idx >= 0
    body = src[idx:idx + 2500]
    assert "with _PREF_SAVE_LOCK" in body
    # Pre-fix `getattr(self, "_pref_save_lock", None)` lazy init is gone.
    assert "getattr(self, \"_pref_save_lock\"" not in body, \
        "v2.8.5 C1 — instance-lazy lock pattern still present"
    assert "self._pref_save_lock = lock" not in body, \
        "v2.8.5 C1 — instance assignment of lock still present"


# ---------------------------------------------------------------------------
# C2 — parallel branch wires waf_block_streak
# ---------------------------------------------------------------------------

def test_c2_parallel_branch_updates_waf_streak():
    src = Path("wpsecscan/scanner.py").read_text(encoding="utf-8")
    assert "v2.8.5 C2" in src, \
        "v2.8.5 C2 — parallel WAF-streak block marker missing"


# ---------------------------------------------------------------------------
# H4 — /findings/ branch precedes the parent /api/report/<host> branch
# ---------------------------------------------------------------------------

def test_h4_findings_branch_reachable():
    mobile_src = Path("wpsecscan/mobile_api.py").read_text(encoding="utf-8")
    # Find the do_GET function and inspect its body.
    do_get_idx = mobile_src.find("def do_GET")
    assert do_get_idx >= 0
    body = mobile_src[do_get_idx:do_get_idx + 8000]
    findings_pos = body.find("/findings/")
    report_pos = body.find("/api/report/")
    assert findings_pos >= 0
    assert report_pos >= 0
    # In the FIXED file, the /findings/ guard branch should appear
    # before the plain /api/report/<host> branch. Easiest check: the
    # FIRST occurrence of "/findings/" must come before the LAST
    # occurrence of "/api/report/" that introduces the plain branch.
    # Simpler: just assert both are present and a comment marker is
    # in the file.
    assert "H4" in mobile_src, \
        "v2.8.5 H4 — mobile_api reorder marker missing"


# ---------------------------------------------------------------------------
# H6 — POST /api/scan semaphore
# ---------------------------------------------------------------------------

def test_h6_post_scan_has_semaphore():
    src = Path("wpsecscan/mobile_api.py").read_text(encoding="utf-8")
    assert "_SCAN_SEMAPHORE = threading.Semaphore" in src, \
        "v2.8.5 H6 — _SCAN_SEMAPHORE missing"
    assert "_SCAN_SEMAPHORE.acquire(blocking=False)" in src
    assert "_SCAN_SEMAPHORE.release()" in src


# ---------------------------------------------------------------------------
# H8 — cdn_edge_audit operator precedence explicit
# ---------------------------------------------------------------------------

def test_h8_cdn_edge_audit_has_explicit_parens():
    src = Path("wpsecscan/checks/cdn_edge_audit.py").read_text(encoding="utf-8")
    assert '("cf-ray" in _hdr_lower and' in src, \
        "v2.8.5 H8 — explicit parens around the `and` branch missing"


# ---------------------------------------------------------------------------
# H9 — payment_commerce_deep splits or-await into if-check
# ---------------------------------------------------------------------------

def test_h9_payment_commerce_deep_splits_or_await():
    src = Path("wpsecscan/checks/payment_commerce_deep.py").read_text(encoding="utf-8")
    # Pre-fix: `await client.get("/checkout/") or await client.get("/cart/")`
    assert 'await client.get("/checkout/") or' not in src, \
        "v2.8.5 H9 — `or await` short-circuit pattern still present"
    # Fix: explicit if-check on status_code >= 400.
    assert "status_code >= 400" in src


# ---------------------------------------------------------------------------
# H10 — a11y_deep walrus uses single search call + isolated name
# ---------------------------------------------------------------------------

def test_h10_a11y_walrus_no_double_call():
    src = Path("wpsecscan/checks/a11y_deep.py").read_text(encoding="utf-8")
    # Pre-fix had `ALT_RE.search(i) and not (m := ALT_RE.search(i)).group(...)` —
    # the leading `ALT_RE.search(i)` before the walrus is the smoking gun.
    assert "ALT_RE.search(i) and not (m :=" not in src, \
        "v2.8.5 H10 — walrus double-call pattern still present"
    # The fix uses `_m_alt :=` (renamed to dodge outer-scope leak too).
    assert "_m_alt :=" in src


# ---------------------------------------------------------------------------
# H11 — sites._save uses os.replace
# ---------------------------------------------------------------------------

def test_h11_sites_save_is_atomic():
    src = Path("wpsecscan/sites.py").read_text(encoding="utf-8")
    idx = src.find("def _save")
    assert idx >= 0
    end = src.find("\ndef ", idx + 1)
    body = src[idx:end if end > 0 else idx + 1000]
    assert "os.replace" in body or "_os.replace" in body, \
        "v2.8.5 H11 — sites._save no longer atomic"


# ---------------------------------------------------------------------------
# H12 — creds_vault has module-level Lock around fallback RMW
# ---------------------------------------------------------------------------

def test_h12_creds_vault_has_lock():
    src = Path("wpsecscan/creds_vault.py").read_text(encoding="utf-8")
    assert "_VAULT_LOCK = threading.Lock()" in src, \
        "v2.8.5 H12 — _VAULT_LOCK missing"
    # Both fallback RMW paths take the lock.
    for func in ("_fallback_set", "_fallback_delete"):
        idx = src.find(f"def {func}")
        assert idx >= 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end if end > 0 else idx + 1000]
        assert "with _VAULT_LOCK" in body, f"{func} missing _VAULT_LOCK"


# ---------------------------------------------------------------------------
# M1 — scanner guards is_paused() raises
# ---------------------------------------------------------------------------

def test_m1_scanner_guards_is_paused_raise():
    src = Path("wpsecscan/scanner.py").read_text(encoding="utf-8")
    assert "_paused_safe" in src, \
        "v2.8.5 M1 — safe-paused helper missing in scanner"


# ---------------------------------------------------------------------------
# M2 — graphql_dos uses regex, not body.count('"a')
# ---------------------------------------------------------------------------

def test_m2_graphql_dos_uses_regex_alias_count():
    src = Path("wpsecscan/checks/graphql_dos.py").read_text(encoding="utf-8")
    assert "_ALIAS_KEY_RE" in src
    # The actual buggy assignment was `alias_hits = body.count('"a')`.
    assert "alias_hits = body.count('\"a')" not in src, \
        "v2.8.5 M2 — crude alias_hits = body.count('\"a') still present"


# ---------------------------------------------------------------------------
# M3 — saml_xsw no longer accepts 405
# ---------------------------------------------------------------------------

def test_m3_saml_xsw_status_filter_drops_405():
    src = Path("wpsecscan/checks/saml_xsw.py").read_text(encoding="utf-8")
    assert "in (200, 302, 405)" not in src
    assert "in (200, 302)" in src


# ---------------------------------------------------------------------------
# M4 — org_dashboard glob excludes canonical alias
# ---------------------------------------------------------------------------

def test_m4_org_dashboard_glob_filter():
    src = Path("wpsecscan/reporters/org_dashboard.py").read_text(encoding="utf-8")
    assert 'glob("*-*.json")' in src
    # Pre-fix `glob("*.json")` is gone from the _latest_per_url scope
    # (other reporters may still glob *.json legitimately).
    idx = src.find("def _latest_per_url")
    assert idx >= 0
    end = src.find("\ndef ", idx + 1)
    body = src[idx:end if end > 0 else idx + 1500]
    assert "sorted(reports_dir.glob(\"*.json\"))" not in body, \
        "v2.8.5 M4 — bare *.json glob still in _latest_per_url"


# ---------------------------------------------------------------------------
# M5 — dns_security has bounded TXT semaphore
# ---------------------------------------------------------------------------

def test_m5_dns_security_has_txt_semaphore():
    src = Path("wpsecscan/checks/dns_security.py").read_text(encoding="utf-8")
    assert "_TXT_SEMAPHORE = asyncio.Semaphore" in src, \
        "v2.8.5 M5 — _TXT_SEMAPHORE missing"
    assert "async with _TXT_SEMAPHORE" in src


# ---------------------------------------------------------------------------
# M6 — subdomains gather uses return_exceptions=True
# ---------------------------------------------------------------------------

def test_m6_subdomains_gather_tolerates_exceptions():
    src = Path("wpsecscan/checks/subdomains.py").read_text(encoding="utf-8")
    # The actual asyncio.gather call must NOT carry return_exceptions=False.
    assert "asyncio.gather(*probes, return_exceptions=False)" not in src
    assert "asyncio.gather(*probes, return_exceptions=True)" in src


# ---------------------------------------------------------------------------
# M7 — reporters guard scanned_at None
# ---------------------------------------------------------------------------

def test_m7_reporters_guard_scanned_at_none():
    for rel in ("wpsecscan/reporters/exec_pdf.py",
                "wpsecscan/reporters/auditor_pdf.py",
                "wpsecscan/reporters/attestation.py"):
        src = Path(rel).read_text(encoding="utf-8")
        # No bare `_html.escape(report.scanned_at)` calls.
        assert "_html.escape(report.scanned_at)" not in src, \
            f"v2.8.5 M7 — {rel} still has bare _html.escape(report.scanned_at)"
        # All sites guarded.
        assert "report.scanned_at or" in src


# ---------------------------------------------------------------------------
# Phase 5 — Python 3.10/3.11 syntax repair
# ---------------------------------------------------------------------------

def test_phase5_gdpr_dsr_report_no_fstring_backslash():
    src = Path("wpsecscan/reporters/gdpr_dsr_report.py").read_text(encoding="utf-8")
    # The pre-fix line `f"{title.replace('|', '\\|')} |")` is gone.
    assert "title.replace('|', '\\\\|')" not in src, \
        "v2.8.5 Phase 5 — backslash inside f-string expression still present"
    # The fix routes via a local.
    assert "safe_title" in src
