"""Round-60 — smoke tests for the 28-feature batch."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx():
    return {"target": "https://example.com", "shared": {}, "step": lambda _s: None}


# ============================================================
# New checks
# ============================================================

def test_wp_multisite_deep_skipped_single_site():
    from wpsecscan.checks.wp_multisite_deep import check
    findings = _run(check(FakeClient(), _ctx()))
    assert isinstance(findings, list)


def test_honeypot_admin_no_indicators():
    from wpsecscan.checks.honeypot_admin import check
    findings = _run(check(FakeClient(), _ctx()))
    assert any("honeypot" in f.title.lower() for f in findings)


def test_a11y_deep_basic():
    from wpsecscan.checks.a11y_deep import check
    body = "<!doctype html><html><body><img src='x'><form><input type=text></form></body></html>"
    findings = _run(check(FakeClient(responses={"/": FakeResponse(text=body)}), _ctx()))
    assert any("WCAG" in f.title for f in findings)


def test_perf_budget_small_page():
    from wpsecscan.checks.perf_budget import check
    findings = _run(check(FakeClient(responses={"/": FakeResponse(text="<html><body>ok</body></html>")}), _ctx()))
    assert isinstance(findings, list) and findings


# ============================================================
# bug_report
# ============================================================

def test_bug_report_system_info():
    from wpsecscan import bug_report
    info = bug_report.system_info()
    assert "wpsecscan_version" in info and "python_version" in info


def test_bug_report_gh_issue_url():
    from wpsecscan import bug_report
    url = bug_report.build_github_issue_url(title="t", repro="r")
    assert "github.com/bryanflowers/wpsecscan/issues/new" in url and "title=t" in url


def test_bug_report_redact_in_log():
    from wpsecscan import bug_report
    url = bug_report.build_github_issue_url(title="t", repro="r",
                                              include_log="Authorization: Bearer abc123def456ghi789jkl012mno345")
    assert "abc123def456ghi789jkl012mno345" not in url


def test_bug_report_glitchtip_no_dsn():
    from wpsecscan import bug_report
    os.environ.pop("WPSECSCAN_GLITCHTIP_DSN", None)
    assert bug_report.submit_to_glitchtip(None) is False


def test_bug_report_send_feedback():
    from wpsecscan import bug_report
    url = bug_report.send_feedback(message="x", category="wrong_finding")
    assert "false-positive" in url


def test_bug_report_list_prior_crashes(tmp_path, monkeypatch):
    from wpsecscan import bug_report
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    (tmp_path / "crash-1.txt").write_text("x")
    (tmp_path / "crash-2.txt").write_text("y")
    rows = bug_report.list_prior_crashes()
    assert len(rows) == 2
    bug_report.mark_crash_status(rows[0]["path"], "dismissed")
    after = bug_report.list_prior_crashes()
    assert any(r["status"] == "dismissed" for r in after)


# ============================================================
# sites + scheduler + digest
# ============================================================

def test_sites_add_and_list(tmp_path, monkeypatch):
    from wpsecscan import sites
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    sites.add("https://a.example", weekly=True)
    sites.add("https://b.example", weekly=False)
    rows = sites.list_sites()
    assert {s["url"] for s in rows} == {"https://a.example", "https://b.example"}
    assert sites.remove("https://a.example") is True


def test_sites_due_now(tmp_path, monkeypatch):
    from wpsecscan import sites
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    sites.add("https://x.example", weekly=True)
    due = sites.due_now()
    assert any(s["url"] == "https://x.example" for s in due)
    sites.mark_scanned("https://x.example", risk_score=42, critical=0, high=1)
    due2 = sites.due_now()
    assert not any(s["url"] == "https://x.example" for s in due2)


def test_sites_render_digest(tmp_path, monkeypatch):
    from wpsecscan import sites
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    sites.add("https://x.example", weekly=True)
    sites.mark_scanned("https://x.example", risk_score=50, critical=1, high=2)
    body = sites.render_digest(sites.list_sites())
    assert "x.example" in body and "critical=1" in body


# ============================================================
# webhooks_chat
# ============================================================

def test_webhooks_chat_no_url():
    from wpsecscan.integrations import webhooks_chat
    rep = {"target": "https://e.com", "risk_score": 0,
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
    assert webhooks_chat.notify_slack("", rep) is False
    assert webhooks_chat.notify_discord("", rep) is False
    assert webhooks_chat.notify_teams("", rep) is False


# ============================================================
# round60 module
# ============================================================


# ============================================================
# auto_remediation
# ============================================================


# ============================================================
# threat_intel
# ============================================================

def test_threat_intel_no_keys():
    from wpsecscan.integrations import threat_intel
    os.environ.pop("VIRUSTOTAL_API_KEY", None)
    out = threat_intel.virustotal_url("https://e.com")
    assert out == {}


# ============================================================
# tor_proxy
# ============================================================

def test_tor_proxy_no_env():
    from wpsecscan.integrations import tor_proxy
    os.environ.pop("WPSECSCAN_PROXY_URL", None)
    out = tor_proxy.check_tor_exit()
    assert out["ok"] is False


# ============================================================
# ticketing
# ============================================================

def test_ticketing_no_creds():
    from wpsecscan.integrations import ticketing
    for k in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_TOKEN", "LINEAR_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        os.environ.pop(k, None)
    assert ticketing.jira_create("X", {"title": "t"}, "https://e.com") == ""
    assert ticketing.linear_create("X", {"title": "t"}, "https://e.com") == ""
    assert ticketing.github_issue_create("a/b", {"title": "t"}, "https://e.com") == ""


# ============================================================
# watchers
# ============================================================

def test_watchers_state_roundtrip(tmp_path, monkeypatch):
    from wpsecscan import watchers
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    out = watchers._load_state("foo")
    assert out == {}
    watchers._save_state("foo", {"bar": 1})
    assert watchers._load_state("foo") == {"bar": 1}


def test_watchers_takeover_rejects_invalid():
    from wpsecscan import watchers
    out = watchers.subdomain_takeover_scan(["good.com", "$(rm -rf /)"])
    # Bad input is silently filtered, no crash
    assert isinstance(out, list)


def test_watchers_dns_invalid_host():
    from wpsecscan import watchers
    assert watchers.dns_change_watcher("$(echo bad)").get("error")


# ============================================================
# Registration sanity
# ============================================================

def test_round_60_checks_registered():
    from wpsecscan.checks import ALL_CHECKS
    registered = {cid for cid, _n, _f, _a in ALL_CHECKS}
    expected = {"wp_multisite_deep", "honeypot_admin", "a11y_deep", "perf_budget"}
    missing = expected - registered
    assert not missing, f"Round-60 checks missing from ALL_CHECKS: {sorted(missing)}"


def test_round_60_tags_present():
    p = Path(__file__).resolve().parents[1] / "wpsecscan" / "data" / "check_tags.json"
    tags = json.loads(p.read_text(encoding="utf-8"))
    for cid in ("wp_multisite_deep", "honeypot_admin", "a11y_deep", "perf_budget"):
        assert cid in tags
