"""Regression tests for the bugs caught by the deep audit:
- csv_out CSV-formula injection neutralisation
- models.Finding severity validation (catches typos at construction)
- gui_payloads._validate_target_url (blocks AWS metadata / loopback)
- authenticated.py doesn't leak username in step() messages
"""
from __future__ import annotations

import io
import csv

import pytest

from wpsecscan.models import Finding, CheckResult, ScanReport
from wpsecscan.reporters import csv_out
from wpsecscan.gui_payloads import _validate_target_url


# ============================== csv injection ==============================

def _build_report(*titles) -> ScanReport:
    findings = [Finding(severity="high", title=t) for t in titles]
    return ScanReport(
        target="https://example.com",
        scanned_at="2026-05-23T00:00:00Z",
        duration_ms=0,
        results=[CheckResult(check_id="x", check_name="x", findings=findings)],
    )


def _parse_csv(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _title_col(rows: list[list[str]]) -> int:
    """Find the title column by header so the test isn't tied to column position."""
    return rows[0].index("title")


def test_csv_neutralizes_equals_formula():
    """Finding title `=cmd|calc.exe` would execute as a formula in Excel. Must be neutralised."""
    r = _build_report("=cmd|calc.exe")
    rows = _parse_csv(csv_out.render(r))
    title_cell = rows[1][_title_col(rows)]
    assert title_cell.startswith("'="), f"expected leading apostrophe, got {title_cell!r}"


def test_csv_neutralizes_plus_minus_at_tab():
    """All formula trigger chars per OWASP must be neutralised."""
    for ch in ("+SUM(1+1)", "-2+3", "@SUM(A1)", "\tx"):
        rows = _parse_csv(csv_out.render(_build_report(ch)))
        title_cell = rows[1][_title_col(rows)]
        assert title_cell.startswith("'"), f"prefix not neutralised for {ch!r}: {title_cell!r}"


def test_csv_normal_titles_unaffected():
    """Findings that don't start with a formula char should round-trip unchanged."""
    rows = _parse_csv(csv_out.render(_build_report("Reflected XSS in ?q=")))
    assert rows[1][_title_col(rows)] == "Reflected XSS in ?q="


# ============================== Finding severity ==============================

def test_finding_rejects_typo_severity():
    with pytest.raises(ValueError, match="severity"):
        Finding(severity="critcial", title="x")  # typo: critcial


def test_finding_rejects_empty_severity():
    with pytest.raises(ValueError):
        Finding(severity="", title="x")


def test_finding_accepts_all_valid_severities():
    for sev in ("info", "low", "medium", "high", "critical"):
        f = Finding(severity=sev, title="x")
        assert f.severity == sev


# ============================== gui_payloads URL validation ==============================

def test_payload_tester_rejects_aws_metadata():
    ok, why = _validate_target_url("http://169.254.169.254/")
    assert not ok and ("private" in why.lower() or "ip" in why.lower())


def test_payload_tester_rejects_loopback():
    ok, why = _validate_target_url("http://127.0.0.1/")
    assert not ok


def test_payload_tester_rejects_localhost_literal():
    ok, why = _validate_target_url("http://localhost/")
    assert not ok and "loopback" in why.lower()


def test_payload_tester_rejects_file_scheme():
    ok, why = _validate_target_url("file:///etc/passwd")
    assert not ok and "scheme" in why.lower()


def test_payload_tester_rejects_private_ip():
    ok, why = _validate_target_url("http://192.168.1.1/")
    assert not ok


def test_payload_tester_accepts_normal_hostname():
    ok, _ = _validate_target_url("https://example.com/wp-login.php")
    assert ok


def test_payload_tester_accepts_subdomain():
    ok, _ = _validate_target_url("https://staging.example.com/")
    assert ok


# ============================== authenticated.py credential leak ==============================

def test_authenticated_step_message_no_username():
    """Read the source to verify we never include {user} in step() calls."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "wpsecscan" / "checks" / "authenticated.py").read_text(encoding="utf-8")
    # Find every step() call line
    bad: list[str] = []
    for i, line in enumerate(src.splitlines(), 1):
        if "step(" in line and ("{user}" in line or "'{user}" in line or "{user!r}" in line):
            bad.append(f"line {i}: {line.strip()}")
    assert not bad, "username appears in step() calls:\n" + "\n".join(bad)


def test_authenticated_completion_evidence_no_username():
    """The 'completed with no critical issues' finding must not embed the username."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "wpsecscan" / "checks" / "authenticated.py").read_text(encoding="utf-8")
    # The old leaky string used a quoted {user} placeholder; verify it's gone.
    assert "Logged in as '{user}'" not in src


# ============================== sarif schema basics ==============================

def test_sarif_renders_minimum_required_fields():
    """SARIF 2.1.0 needs version, runs[].tool.driver.name, ruleId, message.text."""
    from wpsecscan.reporters import sarif
    import json as _j
    r = _build_report("Reflected XSS")
    out = sarif.render(r)
    d = _j.loads(out)
    assert d.get("version") == "2.1.0"
    assert d["runs"][0]["tool"]["driver"]["name"]
    result = d["runs"][0]["results"][0]
    assert result.get("ruleId")
    assert result["message"]["text"]


# ============================== scanner.gather error handling ==============================

def test_scanner_gather_handles_check_exception():
    """One failing check must not kill all the others in concurrent mode."""
    import asyncio
    from wpsecscan.scanner import scan

    # Easiest reproduction: pass a target that resolves but isn't a real WP site;
    # checks will mostly hit timeouts/None responses but must not crash.
    # Skip if no network — this is an integration smoke, not a unit test.
    import socket
    try:
        socket.gethostbyname("example.invalid")
        pytest.skip("DNS resolves invalid TLD; can't run isolation test")
    except socket.error:
        pass
    # Run the scan; we just need it to not raise.
    try:
        asyncio.run(scan("https://example.invalid", timeout=2.0, sequential=False))
    except Exception as e:
        pytest.fail(f"scan() raised in concurrent mode: {e}")
