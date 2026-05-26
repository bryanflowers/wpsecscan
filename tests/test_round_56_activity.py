"""Round-56 activity-bus + console_live + demo tests."""
from __future__ import annotations

from pathlib import Path

import pytest


# ---------------- activity bus ----------------

def test_activity_emit_and_recent():
    from wpsecscan import activity
    activity.clear()
    activity.emit("threat_intel", "test event 1")
    activity.emit("reporter", "test event 2", extra_kb=42)
    events = activity.recent()
    assert len(events) == 2
    assert events[0]["category"] == "threat_intel"
    assert events[1]["message"] == "test event 2"
    assert events[1]["extra"]["extra_kb"] == 42


def test_activity_subscriber_invoked():
    from wpsecscan import activity
    activity.clear()
    received: list[dict] = []
    activity.subscribe(received.append)
    try:
        activity.emit("reporter", "hi")
        assert len(received) == 1
        assert received[0]["message"] == "hi"
    finally:
        activity.unsubscribe(received.append)


def test_activity_broken_subscriber_does_not_break_emit():
    from wpsecscan import activity
    activity.clear()
    def bad(_e): raise RuntimeError("boom")
    good_received: list[dict] = []
    activity.subscribe(bad)
    activity.subscribe(good_received.append)
    try:
        activity.emit("reporter", "still works")
        assert len(good_received) == 1
        # bus should still hold the event despite the subscriber crashing
        assert len(activity.recent()) == 1
    finally:
        activity.unsubscribe(bad)
        activity.unsubscribe(good_received.append)


def test_activity_counts_by_category():
    from wpsecscan import activity
    activity.clear()
    for _ in range(3):
        activity.emit("threat_intel", "x")
    activity.emit("reporter", "y")
    counts = activity.counts_by_category()
    assert counts == {"threat_intel": 3, "reporter": 1}


def test_activity_message_truncation():
    """A runaway message can't OOM the bus — capped at 300 chars."""
    from wpsecscan import activity
    activity.clear()
    activity.emit("meta", "x" * 5000)
    e = activity.recent()[0]
    assert len(e["message"]) <= 300


def test_activity_bounded_deque():
    """Buffer is bounded so very chatty scans don't grow without limit."""
    from wpsecscan import activity
    activity.clear()
    for i in range(500):
        activity.emit("check", f"event {i}")
    events = activity.recent(1000)
    # bus is capped at 200
    assert len(events) <= 200
    # most recent event is preserved
    assert events[-1]["message"] == "event 499"


# ---------------- emit sites wired ----------------


def test_reporter_html_emits(tmp_path):
    """HTML reporter write should emit one reporter event."""
    from wpsecscan import activity
    from wpsecscan.reporters import html as _h
    from wpsecscan.models import ScanReport
    activity.clear()
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    p = tmp_path / "r.html"
    _h.write(rep, p)
    msgs = [e["message"] for e in activity.recent() if e["category"] == "reporter"]
    assert any("HTML" in m for m in msgs)


def test_reporter_json_emits_and_embeds_activity_log(tmp_path):
    """JSON reporter should emit + embed `activity_log` in the saved file."""
    from wpsecscan import activity
    from wpsecscan.reporters import json_out as _j
    from wpsecscan.models import ScanReport
    activity.clear()
    activity.emit("threat_intel", "synthetic kev hit")
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=0)
    p = tmp_path / "r.json"
    _j.write(rep, p)
    import json as _json
    body = _json.loads(p.read_text(encoding="utf-8"))
    assert "activity_log" in body
    assert any(e["category"] == "threat_intel" for e in body["activity_log"])


def test_check_health_emits_on_auto_disable():
    from wpsecscan import check_health, activity
    activity.clear()
    check_health.reset_run()
    # Below threshold — no event
    for _ in range(check_health.FAILURE_THRESHOLD - 1):
        check_health.record_failure("foo")
    assert all(e["category"] != "meta" for e in activity.recent())
    # Crossing the threshold fires exactly one meta event
    check_health.record_failure("foo")
    metas = [e for e in activity.recent() if e["category"] == "meta"]
    assert len(metas) == 1
    assert "foo" in metas[0]["message"]
    check_health.reset_run()


def test_incremental_emits_on_skip(tmp_path, monkeypatch):
    from datetime import datetime
    import json as _json
    from wpsecscan import incremental, activity, history
    monkeypatch.setattr(history, "_home", lambda: tmp_path)
    activity.clear()
    # Create a fresh snapshot so should_skip_check returns True
    safe = history._safe_filename("https://x.com")
    reports = tmp_path / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / f"foo-{safe}-1.json").write_text(
        _json.dumps({"scanned_at": "2030-01-01T00:00:00"}), encoding="utf-8"
    )
    since = datetime(2025, 1, 1)
    # `favicon_hash` is in LOW_CHURN_CHECK_IDS
    assert incremental.should_skip_check("favicon_hash", "https://x.com", since) is True
    assert any(e["category"] == "meta" and "incremental skip" in e["message"]
               for e in activity.recent())


# ---------------- demo ----------------

def test_demo_report_shape():
    from wpsecscan import demo
    rep = demo.build_demo_report()
    assert rep.target == demo.DEMO_TARGET
    assert len(rep.results) >= 20
    # has at least one finding of each severity
    sevs = {f.severity for r in rep.results for f in r.findings}
    assert {"critical", "high", "medium", "low", "info"}.issubset(sevs)


def test_demo_activity_covers_every_category():
    from wpsecscan import demo
    cats = {cat for cat, _msg in demo.DEMO_ACTIVITY}
    # Must hit at least these 5 categories so the live dashboard shows all badges
    assert {"threat_intel", "reporter", "integration", "artifact", "meta"}.issubset(cats)


def test_demo_run_unpaced_completes():
    from wpsecscan import demo, activity
    activity.clear()
    rep = demo.run_demo(paced=False)
    assert rep is not None
    # Activity bus should have populated
    cats = activity.counts_by_category()
    assert sum(cats.values()) >= 15  # ~25 events plus per-finding check events


def test_demo_write_artifacts_creates_files(tmp_path):
    from wpsecscan import demo
    rep = demo.build_demo_report()
    written = demo.write_artifacts(rep, tmp_path)
    # At minimum HTML + JSON should always succeed
    assert "html" in written and written["html"].exists()
    assert "json" in written and written["json"].exists()


# ---------------- console_live ----------------

def test_console_live_constructs_without_terminal():
    """LiveDashboard must be constructible even when the Console isn't a TTY."""
    from rich.console import Console
    from wpsecscan.console_live import LiveDashboard
    c = Console(file=open("nul" if __import__("sys").platform == "win32" else "/dev/null", "w"),
                force_terminal=False)
    dash = LiveDashboard(c, "https://x.com", total_checks=10)
    # Just exercise the layout builder without entering the Live context
    layout = dash._build_layout()
    assert layout is not None


def test_console_live_callback_routes_events():
    """on_progress callback must update internal counters."""
    from rich.console import Console
    from wpsecscan.console_live import LiveDashboard
    from wpsecscan.models import CheckResult, Finding
    c = Console(file=open("nul" if __import__("sys").platform == "win32" else "/dev/null", "w"),
                force_terminal=False)
    dash = LiveDashboard(c, "https://x.com", total_checks=2)
    cb = dash.on_progress_callback()
    cb("start", "cors", "CORS", None)
    assert dash._current_label == "CORS"
    cb("done", "cors", "CORS",
       CheckResult(check_id="cors", check_name="CORS",
                   findings=[Finding(severity="high", title="X")]))
    assert dash._done_count == 1
    assert len(dash._findings_buf) == 1


# ---------------- end-of-scan stats panel ----------------

def test_what_ran_panel_renders():
    """The new What-ran block in console reporter must render without crashing."""
    from rich.console import Console
    from io import StringIO
    from wpsecscan.reporters.console import render, _render_what_ran
    from wpsecscan.models import ScanReport, CheckResult, Finding
    from wpsecscan import activity
    activity.clear()
    activity.emit("threat_intel", "KEV: 1 enriched")
    activity.emit("reporter", "HTML: r.html (47 KB)")
    rep = ScanReport(target="https://x.com", scanned_at="now", duration_ms=1500,
                     results=[CheckResult(check_id="cors", check_name="CORS",
                                          findings=[Finding(severity="high", title="X")],
                                          duration_ms=120)])
    buf = StringIO()
    c = Console(file=buf, force_terminal=False, no_color=True, width=120)
    render(rep, c)
    out = buf.getvalue()
    assert "What ran" in out
    assert "threat-intel" in out
