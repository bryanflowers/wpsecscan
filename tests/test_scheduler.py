"""Wave 3 — tests for wpsecscan/scheduler.py beyond the cron-dow regression
(test_scheduler_cron_dow.py covers the POSIX dow alignment in depth)."""
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

from wpsecscan import scheduler


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own ~/.wpsecscan/ sandbox so persisted state
    doesn't bleed between tests."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    yield


def test_add_and_list_round_trip():
    scheduler.add("0 3 * * 1", "https://a.example", ["--aggressive"], name="weekly-a")
    scheduler.add("*/15 * * * *", "https://b.example", [], name="freq-b")
    entries = scheduler.list_entries()
    assert len(entries) == 2
    assert entries[0].name == "weekly-a"
    assert entries[0].flags == ["--aggressive"]


def test_remove_by_name():
    scheduler.add("0 3 * * 1", "https://x", [], name="alpha")
    scheduler.add("0 3 * * 1", "https://y", [], name="beta")
    assert scheduler.remove("alpha") is True
    names = [e.name for e in scheduler.list_entries()]
    assert "alpha" not in names
    assert "beta" in names


def test_remove_by_index():
    scheduler.add("0 3 * * 1", "https://x", [], name="alpha")
    assert scheduler.remove("0") is True
    assert scheduler.list_entries() == []


def test_remove_nonexistent_returns_false():
    assert scheduler.remove("does-not-exist") is False


def test_parse_field_star():
    assert scheduler._parse_field("*", 0, 5) == {0, 1, 2, 3, 4, 5}


def test_parse_field_step():
    assert scheduler._parse_field("*/10", 0, 59) == {0, 10, 20, 30, 40, 50}


def test_parse_field_range_with_step():
    assert scheduler._parse_field("0-10/2", 0, 59) == {0, 2, 4, 6, 8, 10}


def test_parse_field_list():
    assert scheduler._parse_field("1,5,10", 0, 30) == {1, 5, 10}


def test_matches_minute_hour():
    # 03:30 on any day
    when = datetime(2026, 5, 27, 3, 30)
    assert scheduler.matches("30 3 * * *", when) is True
    assert scheduler.matches("31 3 * * *", when) is False


def test_run_once_skips_disabled():
    entry = scheduler.add("0 3 * * *", "https://x", [], name="disabled-one")
    entry.enabled = False
    scheduler._save([entry])
    when = datetime(2026, 5, 27, 3, 0)
    with patch.object(scheduler.subprocess, "run") as run:
        results = scheduler.run_once(when)
    assert results == []
    run.assert_not_called()


def test_run_once_dispatches_match():
    scheduler.add("0 3 * * *", "https://x", ["--no-console"], name="match-one")
    when = datetime(2026, 5, 27, 3, 0)
    with patch.object(scheduler.subprocess, "run") as run:
        run.return_value = MagicMock(returncode=0)
        results = scheduler.run_once(when)
    assert len(results) == 1
    args, _ = run.call_args
    cmd = args[0]
    assert "https://x" in cmd
    assert "--no-console" in cmd


def test_run_once_anti_double_fire():
    """Running twice in the same minute shouldn't trigger a second time."""
    scheduler.add("0 3 * * *", "https://x", [], name="dedupe-one")
    when = datetime(2026, 5, 27, 3, 0)
    with patch.object(scheduler.subprocess, "run") as run:
        run.return_value = MagicMock(returncode=0)
        scheduler.run_once(when)
        results2 = scheduler.run_once(when)
    assert results2 == []  # second tick deduped
