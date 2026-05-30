"""Regression tests for v2.8.0 Wave 2 — 15 High-severity bugs.

B8 (--format json,html silent override) was a verified FALSE POSITIVE:
the code intentionally clears both *_only flags when both are picked so
the default "write both" output kicks in. Documented in test docstring.

Covered: B6 (duplicate --quiet), B7 (password-audit exit code), B9
(--tldr exit code), B10 (SARIF None title), B11 (console None concat),
B12 (JSON NaN/Infinity), B13 (R2 false positive), B14 (wallet seed
threshold), B15 (subdomains cname_frag wired), B16 (email_security
WPSECSCAN_NO_LIVE gate), B17 (mask_private Unicode email), B18 (TLS
strptime locale), B19 (web push allow-list), B20 (api_server scan-
cap), B21 (real healthz).
"""
import inspect
import math
import os
from pathlib import Path
from unittest.mock import patch

import pytest


def _file(rel: str) -> str:
    import wpsecscan
    return (Path(wpsecscan.__file__).parent / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# B6 — duplicate --quiet/-q registration removed
# ---------------------------------------------------------------------------

def test_b6_quiet_flag_registered_only_once():
    src = _file("__main__.py")
    # The pre-fix duplicate registration `add_argument("--quiet", "-q", dest="no_console"...)`
    # appeared twice; now must appear exactly once (the canonical line
    # that ALSO includes --no-console as a long alias).
    count = src.count('add_argument("--quiet"')
    assert count == 1, (
        f'--quiet registered {count} times; expected exactly 1 (the canonical '
        'spec that includes --no-console as a third alias).'
    )


# ---------------------------------------------------------------------------
# B7 — --password-audit exit code 1 → 2
# ---------------------------------------------------------------------------

def test_b7_password_audit_uses_exit_2_on_bad_input():
    src = _file("__main__.py")
    # The password_audit FileNotFoundError/ValueError handler block
    # must use sys.exit(2) (usage error), not sys.exit(1) (any-finding).
    import re
    m = re.search(
        r"if args\.password_audit:.*?except \(FileNotFoundError, ValueError\).*?sys\.exit\((\d+)\)",
        src, re.DOTALL)
    assert m, "password_audit error-handler block not found"
    assert m.group(1) == "2", (
        f"--password-audit bad-input must exit 2 (usage error), got {m.group(1)}"
    )


# ---------------------------------------------------------------------------
# B9 — --tldr exit code honours --fail-on, not raw severity rank
# ---------------------------------------------------------------------------

def test_b9_tldr_exit_honours_fail_on_contract():
    src = _file("__main__.py")
    # Pre-fix: `return _SEV_RANK.get(worst_sev, 0)` (exit 0-4 by severity).
    # Post-fix: returns 1 if worst_rank >= threshold else 0.
    assert "_SEV_RANK.get(worst_sev, 0)" not in src
    # The new pattern uses SEVERITY_RANK from models + fail_on attr.
    assert "fail_on" in src and "SEVERITY_RANK" in src


# ---------------------------------------------------------------------------
# B10 — SARIF handles None title/evidence
# ---------------------------------------------------------------------------

def test_b10_sarif_no_attribute_error_on_none_fields():
    from wpsecscan.reporters import sarif
    from wpsecscan.models import Finding, CheckResult, ScanReport
    f = Finding(severity="high", title=None, evidence=None)  # type: ignore[arg-type]
    cr = CheckResult(check_id="x", check_name="x", findings=[f])
    rep = ScanReport(target="https://t", scanned_at="now", duration_ms=0, results=[cr])
    # Must not raise.
    out = sarif.render(rep)
    assert "x" in out  # check id appears


# ---------------------------------------------------------------------------
# B11 — console reporter handles None evidence
# ---------------------------------------------------------------------------

def test_b11_console_no_typeerror_on_none_evidence():
    src = _file("reporters/console.py")
    # The pre-fix `details = f.evidence` was unguarded; the fix
    # coerces via `or ""`.
    assert "details = f.evidence or" in src or "details = (f.evidence" in src


# ---------------------------------------------------------------------------
# B12 — JSON reporter handles NaN/Inf
# ---------------------------------------------------------------------------

def test_b12_json_reporter_sanitises_nan():
    from wpsecscan.reporters import json_out
    from wpsecscan.models import Finding, CheckResult, ScanReport
    f = Finding(severity="high", title="t", evidence="e",
                  extra={"ai_score": float("nan"), "perf": float("inf")})
    cr = CheckResult(check_id="x", check_name="x", findings=[f])
    rep = ScanReport(target="https://t", scanned_at="now", duration_ms=0, results=[cr])
    out = json_out.render(rep)
    # NaN/Infinity tokens are NOT in the output (would be invalid JSON).
    assert "NaN" not in out
    assert "Infinity" not in out
    # The output IS valid JSON (parses with the strict stdlib loader).
    import json
    parsed = json.loads(out)
    assert parsed["results"][0]["findings"][0]["extra"]["ai_score"] is None


# ---------------------------------------------------------------------------
# B13 — R2 listing detection now requires XML signature, not just 200
# ---------------------------------------------------------------------------

def test_b13_r2_no_longer_flags_any_200():
    import importlib
    rb = importlib.import_module("wpsecscan.checks.referenced_buckets")
    html_body = b"<!doctype html><html><body><img src='x.png'></body></html>"
    assert rb._is_listing_response("r2", 200, html_body) is False
    xml_body = b"<?xml version='1.0'?><ListBucketResult><contents><key>x</key></contents></ListBucketResult>"
    assert rb._is_listing_response("r2", 200, xml_body) is True


# ---------------------------------------------------------------------------
# B14 — wallet seed threshold now requires all 12 in subset (no FP on prose)
# ---------------------------------------------------------------------------

def test_b14_wallet_seed_threshold_tightened():
    src = _file("checks/wallet_seed_phrase_leak.py")
    # The pre-fix `hits >= 8` is gone; the post-fix uses 12/12.
    assert "hits >= 8" not in src
    assert "hits >= 12" in src


# ---------------------------------------------------------------------------
# B15 — subdomains check uses cname_frag (not just unpacks it)
# ---------------------------------------------------------------------------

def test_b15_subdomains_validates_cname_chain():
    src = _file("checks/subdomains.py")
    # The pre-fix `for _cname_frag, marker in` (underscore-prefixed
    # discard) is gone; the fix references cname_frag in a condition.
    assert "for _cname_frag, marker in" not in src
    # The fix uses the cname_frag variable in a check.
    assert "cname_frag" in src and "cname_chain" in src


# ---------------------------------------------------------------------------
# B16 — email_security_deep honours WPSECSCAN_NO_LIVE
# ---------------------------------------------------------------------------

def test_b16_email_security_respects_no_live(monkeypatch):
    import importlib
    esd = importlib.import_module("wpsecscan.checks.email_security_deep")
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")
    with patch("subprocess.run") as mock_run:
        out = esd._resolve_txt("example.com")
    assert out == []
    assert mock_run.called is False


# ---------------------------------------------------------------------------
# B17 — mask_private redacts Unicode emails
# ---------------------------------------------------------------------------

def test_b17_mask_private_redacts_idn_email():
    from wpsecscan.ai_safety import mask_private
    s = "user@münchen.de"
    out = mask_private(s)
    assert "user@münchen.de" not in out, "IDN email not redacted"
    assert "[EMAIL]" in out


def test_b17_mask_private_redacts_unicode_local_part():
    from wpsecscan.ai_safety import mask_private
    s = "田中@example.com"
    out = mask_private(s)
    assert "田中" not in out
    assert "[EMAIL]" in out


# ---------------------------------------------------------------------------
# B18 — TLS cert-date parser is locale-independent
# ---------------------------------------------------------------------------

def test_b18_tls_date_parser_independent_of_locale():
    from wpsecscan.checks.tls_deep import _parse_cert_date_en
    # Standard X.509 date — must parse regardless of process locale.
    dt = _parse_cert_date_en("Jan 24 12:34:56 2026 GMT")
    assert dt is not None
    assert dt.year == 2026 and dt.month == 1 and dt.day == 24
    # Malformed input returns None (not raises).
    assert _parse_cert_date_en("Oca 24 12:34:56 2026 GMT") is None  # Turkish month
    assert _parse_cert_date_en("garbage") is None
    assert _parse_cert_date_en("") is None


# ---------------------------------------------------------------------------
# B19 — web_push_register refuses non-allowlist endpoints
# ---------------------------------------------------------------------------

def test_b19_web_push_refuses_attacker_endpoint():
    from wpsecscan import mobile_v27
    with pytest.raises(ValueError, match="allow-list"):
        mobile_v27.web_push_register(
            "https://evil.example.com/push", "p256dh-data", "auth-data")


def test_b19_web_push_allowlist_helper():
    from wpsecscan.mobile_v27 import _web_push_endpoint_is_allowed
    assert _web_push_endpoint_is_allowed(
        "https://fcm.googleapis.com/fcm/send/abc") is True
    assert _web_push_endpoint_is_allowed(
        "https://updates.push.services.mozilla.com/wpush/v2/xyz") is True
    assert _web_push_endpoint_is_allowed("http://fcm.googleapis.com/x") is False  # not https
    assert _web_push_endpoint_is_allowed("https://evil.example.com/x") is False


def test_b19_web_push_extra_hosts_env(monkeypatch):
    from wpsecscan.mobile_v27 import _web_push_endpoint_is_allowed
    monkeypatch.setenv("WPSECSCAN_WEB_PUSH_EXTRA_HOSTS",
                        "push.example.org, custom.relay.dev")
    assert _web_push_endpoint_is_allowed(
        "https://push.example.org/v1/push") is True


# ---------------------------------------------------------------------------
# B20 — api_server enforces concurrent-scan cap
# ---------------------------------------------------------------------------

def test_b20_api_server_has_scan_slot_semaphore():
    from wpsecscan import api_server
    assert hasattr(api_server, "_SCAN_SLOTS")
    assert hasattr(api_server, "_try_acquire_scan_slot")
    assert hasattr(api_server, "_release_scan_slot")


# ---------------------------------------------------------------------------
# B21 — /healthz distinguishes liveness vs readiness
# ---------------------------------------------------------------------------

def test_b21_healthz_returns_real_readiness_signals():
    src = _file("api_server.py")
    # The unconditional `{"ok": True}` healthz is gone.
    assert 'self._send_json(200, {"ok": True})' not in src
    # The fix surfaces `scan_slots_free` and `ready` keys.
    assert "scan_slots_free" in src
    assert '"ready"' in src
    assert "/readyz" in src
