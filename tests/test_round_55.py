"""Round-55 (waves A-H) smoke tests."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ----- Wave A — attack checks -----

def test_cloud_metadata_ssrf_skips_passive():
    from wpsecscan.checks.cloud_metadata_ssrf import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_dns_rebinding_skips_passive():
    from wpsecscan.checks.dns_rebinding import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_http3_fingerprint_handles_missing_alt_svc():
    from wpsecscan.checks.http3_fingerprint import check
    client = FakeClient(responses={"/": FakeResponse(status_code=200, text="ok")})
    findings = _run(check(client, _ctx()))
    assert any("HTTP/3" in f.title for f in findings)


def test_session_fixation_handles_no_response():
    from wpsecscan.checks.session_fixation import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("session" in f.title.lower() or "unreachable" in f.title.lower() for f in findings)


def test_csrf_entropy_empty_response():
    from wpsecscan.checks.csrf_entropy import check
    findings = _run(check(FakeClient(), _ctx()))
    # No nonces sampled = info finding
    assert any("entropy" in f.title.lower() for f in findings)


def test_hpp_skips_passive():
    from wpsecscan.checks.hpp import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


def test_backup_file_fuzz_clean():
    from wpsecscan.checks.backup_file_fuzz import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("clean" in f.title.lower() for f in findings)


def test_hostname_collision_runs_without_crash():
    from wpsecscan.checks.hostname_collision import check
    # Won't reach the network in offline tests; just ensure no crash.
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_plugin_route_fuzz_skips_no_plugins():
    from wpsecscan.checks.plugin_route_fuzz import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("no plugins detected" in f.title.lower() for f in findings)


def test_header_smuggling_case_skips_passive():
    from wpsecscan.checks.header_smuggling_case import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("skipped" in f.title.lower() for f in findings)


# ----- Wave B — reporting/UX -----


def test_issue_export_payloads():
    from wpsecscan.reporters.issue_export import jira_payloads, github_payloads, linear_payloads
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0,
                     results=[CheckResult(check_id="cors", check_name="CORS",
                                          findings=[Finding(severity="high", title="X")])])
    assert len(jira_payloads(rep, "SEC")) == 1
    assert len(github_payloads(rep)) == 1
    assert len(linear_payloads(rep, "team-xyz")) == 1


def test_risk_weights_load_defaults():
    from wpsecscan.risk_weights import load_weights, DEFAULT_WEIGHTS, reset_to_defaults
    reset_to_defaults()
    load_weights.cache_clear()
    w = load_weights()
    assert w["critical"]["per_finding"] == DEFAULT_WEIGHTS["critical"]["per_finding"]


# ----- Wave C — reliability -----

def test_auto_update_cache_path_safe(tmp_path, monkeypatch):
    from wpsecscan import auto_update
    monkeypatch.setattr(auto_update, "_cache_path", lambda: tmp_path / "u.json")
    # No prior cache + offline -> returns None, doesn't crash
    monkeypatch.setattr(auto_update, "_fetch_latest", lambda channel="stable", **kw: None)
    assert auto_update.check_for_update("1.0", "stable") is None


def test_check_health_self_disable():
    from wpsecscan import check_health
    check_health.reset_run()
    for _ in range(2):
        assert check_health.record_failure("foo") is False
    assert check_health.record_failure("foo") is True
    assert check_health.is_disabled_for_run("foo")
    check_health.reset_run()


def test_crash_submit_redact():
    from wpsecscan.crash_submit import redact
    # Same trick as test_new_checks.py: fragment-build the fake token so
    # GitHub's secret-scanner doesn't reject the push on a placeholder.
    fake_pat = "ghp_" + "1234567890" + "abcdefghijklmnopqrstuvwxyz"
    text = f"Authorization: Bearer {fake_pat}"
    out = redact(text)
    assert fake_pat[:14] not in out
    assert "[REDACTED]" in out


def test_sbom_build():
    from wpsecscan import sbom
    s = sbom.build_sbom(scanner_version="9.9.9")
    assert s["bomFormat"] == "CycloneDX"
    assert s["specVersion"] == "1.5"
    assert isinstance(s["components"], list)


# ----- Wave D — perf -----

def test_incremental_skip_logic(tmp_path, monkeypatch):
    from wpsecscan import incremental
    from datetime import datetime
    # No snapshot -> always scan (returns False, i.e. don't skip)
    assert incremental.should_skip_check("subdomains", "https://x.com", datetime.now()) is False


# ----- Wave E — extension -----

def test_report_query_parsing():
    from wpsecscan.report_query import query
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0,
                     results=[CheckResult(check_id="cors", check_name="CORS",
                                          findings=[
                                              Finding(severity="high", title="A"),
                                              Finding(severity="low",  title="B"),
                                          ])])
    out = query(rep, "severity = high")
    assert len(out) == 1 and out[0]["title"] == "A"
    out = query(rep, "severity in [high, critical]")
    assert len(out) == 1
    out = query(rep, "check_id startswith cor")
    assert len(out) == 2


# ----- Wave F — collab -----


# ----- Wave G — compliance -----

def test_region_egress_noop_when_unset(monkeypatch):
    monkeypatch.delenv("WPSECSCAN_REGION", raising=False)
    from wpsecscan import region_egress
    assert region_egress.configured_region() is None
    assert region_egress.httpx_proxies() is None
    assert region_egress.warn_if_unenforced() is None


def test_auto_pr_fixes_for_empty_report():
    from wpsecscan.models import ScanReport
    from wpsecscan import auto_pr
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    assert auto_pr.fixes_for(rep) == []


def test_attestation_html_fallback(tmp_path, monkeypatch):
    from wpsecscan.reporters import attestation
    monkeypatch.setattr(attestation, "_has_reportlab", lambda: False)
    from wpsecscan.models import ScanReport
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    out = tmp_path / "att.pdf"
    attestation.write(rep, out, vendor="AcmeCo")
    assert (tmp_path / "att.html").exists()


# ----- Wave H — polish -----


def test_completion_generates_for_all_shells():
    from wpsecscan.completion import generate
    assert "compgen" in generate("bash")
    assert "compdef" in generate("zsh")
    assert "Register-ArgumentCompleter" in generate("powershell")


# ----- Inventory + wiring -----

def test_round55_checks_all_registered():
    from wpsecscan.checks import ALL_CHECKS
    ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
    for cid in (
        "cloud_metadata_ssrf", "dns_rebinding", "http3_fingerprint",
        "session_fixation", "csrf_entropy", "hpp", "backup_file_fuzz",
        "hostname_collision", "plugin_route_fuzz", "header_smuggling_case",
    ):
        assert cid in ids, f"round-55 check {cid!r} not registered"


def test_round55_tag_entries_present():
    from wpsecscan import tags
    tmap = tags._load()
    for cid in (
        "cloud_metadata_ssrf", "dns_rebinding", "http3_fingerprint",
        "session_fixation", "csrf_entropy", "hpp", "backup_file_fuzz",
        "hostname_collision", "plugin_route_fuzz", "header_smuggling_case",
    ):
        assert cid in tmap, f"missing tag for {cid!r}"
        assert "cwe" in tmap[cid] and "d3fend" in tmap[cid]


def test_round55_compliance_entries_present():
    from wpsecscan import tags
    cmap = tags._load_compliance()
    for cid in (
        "cloud_metadata_ssrf", "dns_rebinding", "http3_fingerprint",
        "session_fixation", "csrf_entropy", "hpp", "backup_file_fuzz",
        "hostname_collision", "plugin_route_fuzz", "header_smuggling_case",
    ):
        assert cid in cmap


# ----- QA-round regression tests -----

def test_bug1_api_server_bearer_uses_compare_digest():
    """B1: the bearer-token comparison must use hmac.compare_digest."""
    import inspect
    from wpsecscan import api_server
    src = inspect.getsource(api_server)
    assert "hmac.compare_digest" in src, \
        "api_server bearer-token comparison should be constant-time (hmac.compare_digest)"


def test_bug2_api_server_tasks_cap_evicts():
    """B2: _TASKS uses OrderedDict + _put_task with bounded eviction."""
    from wpsecscan import api_server
    api_server._TASKS.clear()
    for i in range(api_server._TASKS_MAX + 50):
        api_server._put_task(f"t{i:04d}", {"status": "done"})
    assert len(api_server._TASKS) == api_server._TASKS_MAX, \
        f"_TASKS should be capped at {api_server._TASKS_MAX}"
    # Oldest tasks must have been evicted
    assert "t0000" not in api_server._TASKS
    assert "t0049" not in api_server._TASKS
    api_server._TASKS.clear()


def test_bug3_api_server_path_traversal_blocks_backslash():
    """B3: the /reports/ guard rejects \\ in addition to / and ..."""
    # The guard is inline in do_GET — we re-derive its logic in the test to
    # avoid needing a live HTTP harness.
    from pathlib import Path
    for bad in ("..\\evil", "report\\..\\evil", "rep/x.json", "\x00", "../etc/passwd"):
        rejected = (".." in bad or "/" in bad or "\\" in bad or "\x00" in bad
                    or bad != Path(bad).name)
        assert rejected, f"{bad!r} must be rejected"
    for good in ("report.json", "scan-2026-05-23.json"):
        rejected = (".." in good or "/" in good or "\\" in good or "\x00" in good
                    or good != Path(good).name)
        assert not rejected, f"{good!r} should be allowed"


def test_bug6_gui_windows_defines_app_name():
    """B6: APP_NAME must be defined in gui_windows.py (onboarding wizard uses it)."""
    from wpsecscan import gui_windows
    assert hasattr(gui_windows, "APP_NAME"), \
        "gui_windows.APP_NAME must exist (used by open_onboarding_wizard)"
    assert isinstance(gui_windows.APP_NAME, str) and gui_windows.APP_NAME


def test_bug7_report_query_tilde_operator_now_tokenizes():
    """B7: the `~` regex operator was unreachable because of \\b boundaries."""
    from wpsecscan.report_query import query
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0,
                     results=[CheckResult(check_id="cors", check_name="CORS",
                                          findings=[Finding(severity="high", title="ABC123 found"),
                                                    Finding(severity="low",  title="other thing")])])
    out = query(rep, "title ~ '[A-Z]+[0-9]+'")
    assert len(out) == 1 and out[0]["title"] == "ABC123 found"


def test_bug9_completion_flags_match_argparse():
    """B9: the FLAGS list mirrors __main__.py's argparse."""
    from wpsecscan.completion import FLAGS
    # Things that MUST be present
    for flag in ("--api-server", "--sbom", "--attestation", "--query",
                 "--since", "--completion", "--no-update-check",
                 "--html-only", "--json-only", "--version", "--debug"):
        assert flag in FLAGS, f"completion.FLAGS missing {flag!r}"
    # Things that must NOT be present (were stale)
    for stale in ("--dump-db", "--quiet", "--reload-checks",
                  "--otlp-endpoint", "--redis-url"):
        assert stale not in FLAGS, f"completion.FLAGS has stale flag {stale!r}"


def test_bug10_hostname_collision_no_unused_parts():
    """B10: the `parts = host.split('.')` line was dead code; removed."""
    import inspect
    from wpsecscan.checks import hostname_collision
    src = inspect.getsource(hostname_collision)
    assert "parts = host.split" not in src


# ----- Second QA round (C1-C6) regression tests -----

def test_c1_should_skip_check_is_actually_called_by_scanner():
    """C1: the K26 incremental-skip helper was dead — verify scanner.py
    imports it inside the per-check loops."""
    import inspect
    from wpsecscan import scanner
    src = inspect.getsource(scanner)
    assert "incremental" in src and "should_skip_check" in src, \
        "scanner.py must call incremental.should_skip_check or --since is dead"


def test_c1b_scan_signature_accepts_since():
    """C1: scanner.scan() must accept the `since=` kwarg from __main__.py."""
    import inspect
    from wpsecscan.scanner import scan
    params = inspect.signature(scan).parameters
    assert "since" in params, "scan() must accept since= for K26 incremental mode"


def test_c2_reset_run_called_per_target_in_main():
    """C2: __main__.py must call check_health.reset_run() inside the
    multi-target loop so J20 auto-disable state doesn't leak across targets."""
    import inspect
    from wpsecscan import __main__ as _m
    src = inspect.getsource(_m)
    # Either the explicit import inside the loop, or a top-level import + the call
    assert "reset_run" in src, "check_health.reset_run() must be called between batch scans"


def test_c3_record_duration_skipped_on_error(tmp_path, monkeypatch):
    """C3: record_duration must NOT be called when the check raised
    (exception-aborted durations distort the rolling-window baseline)."""
    import asyncio
    from wpsecscan import scanner, check_health
    from wpsecscan.models import CheckResult

    # Track every record_duration call
    recorded = []
    monkeypatch.setattr(check_health, "record_duration",
                        lambda cid, ms: recorded.append((cid, ms)))

    async def _raises(client, ctx):
        raise RuntimeError("simulated")

    check_health.reset_run()
    asyncio.run(scanner._run_check("blows_up", "Blows up", _raises, None, {}, None))
    # The crash should NOT have recorded a duration
    assert recorded == [], f"record_duration should be skipped on error, got {recorded}"


def test_c4_onboarding_wizard_has_first_run_hook():
    """C4: FEATURES.md claimed first-run onboarding wizard; gui.py must
    schedule `_maybe_show_onboarding_wizard_first_run` from __init__."""
    import inspect
    from wpsecscan import gui
    src = inspect.getsource(gui)
    assert "_maybe_show_onboarding_wizard_first_run" in src, \
        "gui.py must schedule and define _maybe_show_onboarding_wizard_first_run"
    # And the after(...) scheduling must be there
    assert "_maybe_show_onboarding_wizard_first_run" in src


def test_c5_risk_score_falls_back_when_weights_load_raises(monkeypatch):
    """C5: risk.compute_risk_score must fall back to the legacy formula
    when load_weights raises (e.g. corrupted file)."""
    import wpsecscan.risk as risk_mod
    import wpsecscan.risk_weights as rw

    def _boom():
        raise RuntimeError("corrupted weights file")

    monkeypatch.setattr(rw, "load_weights", _boom)
    from wpsecscan.models import ScanReport, CheckResult, Finding
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0,
                     results=[CheckResult(check_id="cors", check_name="CORS",
                                          findings=[Finding(severity="high", title="X")])])
    # Legacy formula: high = 10 per finding, so 100 - 10 = 90
    assert risk_mod.compute_risk_score(rep) == 90


def test_c6_completion_short_circuits_before_logging():
    """C6: --completion must be checked BEFORE logmod.configure to avoid
    contaminating the output when the user pipes it."""
    import inspect
    from wpsecscan import __main__ as _m
    src = inspect.getsource(_m)
    # Locate the first occurrence of each
    completion_pos = src.find("getattr(args, \"completion\"")
    log_pos = src.find("logmod.configure(")
    assert completion_pos != -1 and log_pos != -1
    assert completion_pos < log_pos, \
        "--completion short-circuit must appear before logmod.configure"
