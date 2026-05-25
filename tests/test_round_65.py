"""Round-65 — Group C (AI triage) + opt-in analytics."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ============================================================
# Group C — AI triage settings + availability
# ============================================================


def test_ai_triage_settings_default_all_off(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    s = ai_triage.AITriageSettings()
    assert s.any_enabled() is False


def test_ai_triage_settings_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    s = ai_triage.AITriageSettings(severity_auto_tuner=True, fp_auto_hide_threshold=0.7)
    s.save()
    loaded = ai_triage.AITriageSettings.load()
    assert loaded.severity_auto_tuner is True
    assert loaded.fp_auto_hide_threshold == 0.7


def test_ai_triage_is_available_returns_false_without_backend(monkeypatch, tmp_path):
    """No OpenAI/Anthropic/Ollama => not available."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    # Patch ai_assist.is_configured to False
    monkeypatch.setattr(ai_triage.ai_assist, "is_configured", lambda: False)
    ok, reason = ai_triage.is_available()
    assert ok is False and "backend" in reason


def test_ai_triage_is_available_false_with_backend_but_no_toggles(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    monkeypatch.setattr(ai_triage.ai_assist, "is_configured", lambda: True)
    ok, reason = ai_triage.is_available()
    assert ok is False and "enable" in reason.lower()


def test_ai_triage_skips_when_disabled(monkeypatch, tmp_path):
    """Even with toggles off, calling features should not raise."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    # Stub ai_assist to count calls
    calls = []
    monkeypatch.setattr(ai_triage.ai_assist, "llm", lambda *a, **kw: calls.append(1) or "")
    monkeypatch.setattr(ai_triage.ai_assist, "is_configured", lambda: True)
    # All toggles off
    result = ai_triage.auto_tune_severity([{"title": "x", "severity": "high"}])
    assert calls == []  # no LLM call made
    # Result is the unchanged input
    assert len(result) == 1


def test_ai_triage_cli_set_and_get(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage, ai_triage_ui
    importlib.reload(ai_triage)
    importlib.reload(ai_triage_ui)
    assert ai_triage_ui.cli_set("severity_auto_tuner", "true") == "ok"
    assert ai_triage_ui.cli_get("severity_auto_tuner") == "True"
    assert ai_triage_ui.cli_set("nonexistent", "x").startswith("unknown")


def test_apply_all_returns_skipped_when_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import ai_triage
    importlib.reload(ai_triage)
    monkeypatch.setattr(ai_triage.ai_assist, "is_configured", lambda: False)
    out = ai_triage.apply_all_enabled({"target": "x", "summary": {}})
    assert "_skipped" in out


# ============================================================
# Analytics — privacy guarantees
# ============================================================


def test_analytics_default_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    s = analytics.AnalyticsSettings.load()
    assert s.enabled is False


def test_analytics_record_is_noop_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.record("cli_command", subcommand="scan", duration_ms=100, exit_status="ok")
    # No file written
    assert not (tmp_path / "analytics" / "events.jsonl").exists()


def test_analytics_enable_disable_round_trip(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    out = analytics.enable()
    assert "ENABLED" in out
    s = analytics.AnalyticsSettings.load()
    assert s.enabled is True and s.enabled_at is not None
    out2 = analytics.disable()
    assert "DISABLED" in out2
    s2 = analytics.AnalyticsSettings.load()
    assert s2.enabled is False


def test_analytics_records_event_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    analytics.record("cli_command", subcommand="scan", duration_ms=120, exit_status="ok")
    p = tmp_path / "analytics" / "events.jsonl"
    assert p.exists()
    line = p.read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert entry["event"] == "cli_command"
    assert entry["fields"]["subcommand"] == "scan"
    assert "anon_id" in entry


def test_analytics_strips_disallowed_fields(monkeypatch, tmp_path):
    """Defence in depth — any extra field a caller might pass is dropped."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    # Pass a URL — should NOT be recorded
    analytics.record("cli_command", subcommand="scan", duration_ms=100, exit_status="ok",
                     target_url="https://secret.example.com", api_key="should-not-leak")
    line = (tmp_path / "analytics" / "events.jsonl").read_text(encoding="utf-8").strip()
    entry = json.loads(line)
    assert "target_url" not in entry["fields"]
    assert "api_key" not in entry["fields"]
    assert "https://secret.example.com" not in json.dumps(entry)


def test_analytics_unknown_event_type_dropped(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    analytics.record("EXFIL_USER_DATA", subcommand="scan")
    assert not (tmp_path / "analytics" / "events.jsonl").exists()


def test_analytics_finding_count_bucketed(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    analytics.record("check_ran", check_id="tls_headers", duration_ms=100, finding_count=42)
    entry = json.loads((tmp_path / "analytics" / "events.jsonl").read_text(encoding="utf-8").strip())
    # 42 -> "26-100" bucket
    assert entry["fields"]["finding_count_bucket"] == "26-100"
    assert "finding_count" not in entry["fields"]  # raw int dropped


def test_analytics_forget_deletes_local_data(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    analytics.record("cli_command", subcommand="scan", duration_ms=10, exit_status="ok")
    assert (tmp_path / "analytics" / "events.jsonl").exists()
    out = analytics.forget()
    assert "Deleted" in out
    assert not (tmp_path / "analytics" / "events.jsonl").exists()
    assert not (tmp_path / "analytics" / "anonymous_id.txt").exists()


def test_analytics_status_includes_path(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    st = analytics.status()
    assert st["enabled"] is False
    assert "events.jsonl" in st["storage_path"]


def test_analytics_show_recent_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    out = analytics.show_recent()
    assert "No analytics events" in out


def test_analytics_time_block_records_duration(monkeypatch, tmp_path):
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    import time
    from wpsecscan import analytics
    importlib.reload(analytics)
    analytics.enable()
    with analytics.time_block("cli_command", subcommand="scan"):
        time.sleep(0.05)
    entry = json.loads((tmp_path / "analytics" / "events.jsonl").read_text(encoding="utf-8").strip())
    assert entry["fields"]["duration_ms"] >= 30
    assert entry["fields"]["exit_status"] == "ok"


def test_analytics_anon_id_quarterly(monkeypatch, tmp_path):
    """Same call returns same UUID within the quarter."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    import importlib
    from wpsecscan import analytics
    importlib.reload(analytics)
    id1 = analytics._get_or_make_anon_id()
    id2 = analytics._get_or_make_anon_id()
    assert id1 == id2
    assert len(id1) >= 32  # UUID-shaped
