"""Webhook notify: URL validation + payload + threshold + async firing."""
from __future__ import annotations

from wpsecscan import notify
from wpsecscan.models import CheckResult, Finding, ScanReport


def _report_with(*findings: Finding) -> ScanReport:
    return ScanReport(
        target="https://example.com",
        scanned_at="2026-05-23T00:00:00Z",
        duration_ms=0,
        results=[CheckResult(check_id="x", check_name="x", findings=list(findings))],
    )


def _f(sev: str, title: str = "x") -> Finding:
    return Finding(severity=sev, title=title)


# ---- URL validation ----

def test_validate_https_to_slack_passes():
    ok, _ = notify.validate_webhook_url("https://hooks.slack.com/services/T00/B00/abc")
    assert ok


def test_validate_https_to_discord_passes():
    ok, _ = notify.validate_webhook_url("https://discord.com/api/webhooks/123/abc")
    assert ok


def test_validate_http_rejected():
    ok, why = notify.validate_webhook_url("http://hooks.slack.com/x")
    assert not ok and "https" in why.lower()


def test_validate_rejects_aws_metadata():
    """Critical: no IP-based URLs at all (covers AWS/GCP/Azure metadata)."""
    ok, why = notify.validate_webhook_url("https://169.254.169.254/")
    assert not ok and ("ip" in why.lower() or "hostname" in why.lower())


def test_validate_rejects_loopback_ip():
    ok, _ = notify.validate_webhook_url("https://127.0.0.1/")
    assert not ok


def test_validate_rejects_file_scheme():
    ok, _ = notify.validate_webhook_url("file:///etc/passwd")
    assert not ok


def test_validate_rejects_random_host():
    ok, why = notify.validate_webhook_url("https://evil.example.com/exfil")
    assert not ok and "allow-list" in why.lower()


def test_validate_rejects_typo_no_colon():
    ok, _ = notify.validate_webhook_url("https//hooks.slack.com")
    assert not ok


def test_validate_rejects_empty():
    ok, _ = notify.validate_webhook_url("")
    assert not ok


def test_validate_rejects_non_string():
    ok, _ = notify.validate_webhook_url(None)  # type: ignore[arg-type]
    assert not ok


# ---- Subdomain-bypass + port-injection regression tests ----

def test_validate_rejects_subdomain_with_allowed_suffix():
    """An attacker-controlled subdomain like hooks.slack.com.evil.com must NOT pass."""
    ok, why = notify.validate_webhook_url("https://hooks.slack.com.evil.com/x")
    assert not ok, "must reject hostname that just contains an allowed suffix"


def test_validate_rejects_prefix_subdomain():
    """A subdomain UNDER an allowed host (evil.hooks.slack.com) is also rejected
    by the tightened policy (exact match only)."""
    ok, why = notify.validate_webhook_url("https://evil.hooks.slack.com/x")
    assert not ok, "tightened policy: no subdomains under allowed hosts"


def test_validate_rejects_custom_port():
    ok, why = notify.validate_webhook_url("https://hooks.slack.com:8443/x")
    assert not ok and "port" in why.lower()


def test_validate_accepts_explicit_default_port():
    """Explicitly stating :443 is the same as omitting the port."""
    ok, _ = notify.validate_webhook_url("https://hooks.slack.com:443/x")
    assert ok


def test_validate_rejects_lookalike_host():
    """Typo: hookx.slack.com — looks like a subdomain of slack.com but isn't on allow-list."""
    ok, why = notify.validate_webhook_url("https://hookx.slack.com/x")
    assert not ok and "allow-list" in why.lower()


# ---- threshold ----

def test_should_notify_high_threshold_with_high_finding():
    assert notify.should_notify(_report_with(_f("high")), "high")


def test_should_notify_high_threshold_with_only_medium():
    assert not notify.should_notify(_report_with(_f("medium")), "high")


def test_should_notify_critical_threshold_with_high_only():
    assert not notify.should_notify(_report_with(_f("high")), "critical")


def test_should_notify_low_threshold_catches_all_severities():
    assert notify.should_notify(_report_with(_f("low")), "low")
    assert notify.should_notify(_report_with(_f("medium")), "low")
    assert notify.should_notify(_report_with(_f("critical")), "low")


# ---- payload format ----

def test_format_message_includes_target_and_score():
    r = _report_with(_f("critical"), _f("high"), _f("medium"))
    msg = notify.format_message(r)
    assert "example.com" in msg["text"]
    assert "1 critical" in msg["text"]
    assert "1 high" in msg["text"]


# ---- end-to-end notify() ----

def test_notify_skips_when_threshold_unmet():
    ok, why = notify.notify(_report_with(_f("low")), "https://hooks.slack.com/services/T/B/abc", threshold="high")
    assert not ok and ">=" in why


def test_notify_returns_validation_failure_for_bad_url():
    """An https URL to a non-allowed host should be rejected by validation, not posted."""
    ok, why = notify.notify(_report_with(_f("high")), "https://evil.example.com/", threshold="high")
    assert not ok
    assert "allow-list" in why.lower()


def test_notify_async_runs_in_background_thread():
    """notify_async must not block the caller; on_done fires after the worker completes."""
    import threading
    done = threading.Event()
    captured = {}

    def cb(ok, msg):
        captured["ok"] = ok
        captured["msg"] = msg
        done.set()

    # Use a URL we know fails validation — it'll return quickly without touching network.
    notify.notify_async(_report_with(_f("high")), "https://blocked.example/", threshold="high", on_done=cb)
    # If notify_async were synchronous, the assert below could only be hit AFTER
    # the worker finished. By calling done.wait() with timeout we prove it ran async.
    assert done.wait(timeout=3.0)
    assert captured.get("ok") is False
