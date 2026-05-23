"""J20 Self-healing + J21 budget tracker.

J20: tracks per-check failure counts in process memory. After 3 timeouts /
exceptions in one scan, the check is auto-disabled for the rest of the run
(NOT persisted — next scan re-enables it).

J21: tracks median duration per check across recent scans (rolling window
in ~/.wpsecscan/check_durations.json). If a check exceeds 5× its rolling
median, emit a warning so the user knows where time is being spent.

Both are advisory — they don't block the scan, they just record signals.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from statistics import median


# ----- J20 in-process self-healing -----

_failures: dict[str, int] = defaultdict(int)
_disabled_this_run: set[str] = set()
FAILURE_THRESHOLD = 3


def record_failure(check_id: str) -> bool:
    """Record a failure for this check. Returns True if the check should now
    be auto-disabled for the rest of this scan."""
    _failures[check_id] += 1
    if _failures[check_id] >= FAILURE_THRESHOLD:
        was_new = check_id not in _disabled_this_run
        _disabled_this_run.add(check_id)
        if was_new:
            try:
                from . import activity as _act
                _act.emit("meta",
                          f"check auto-disabled: {check_id} ({FAILURE_THRESHOLD} consecutive failures)")
            except ImportError:
                pass
        return True
    return False


def is_disabled_for_run(check_id: str) -> bool:
    return check_id in _disabled_this_run


def reset_run() -> None:
    """Clear per-scan state (call between scans in batch mode)."""
    _failures.clear()
    _disabled_this_run.clear()


# ----- J21 budget tracker -----

ROLLING_WINDOW = 20  # last N runs per check


def _durations_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "check_durations.json"


def _load_durations() -> dict[str, list[int]]:
    p = _durations_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return {k: [int(x) for x in v if isinstance(x, (int, float))]
                for k, v in d.items() if isinstance(v, list)}
    except (OSError, ValueError):
        return {}


def _save_durations(d: dict[str, list[int]]) -> None:
    try:
        _durations_path().write_text(json.dumps(d), encoding="utf-8")
    except OSError:
        pass


def record_duration(check_id: str, ms: int) -> None:
    """Append a duration to the rolling window. Trims to ROLLING_WINDOW."""
    d = _load_durations()
    arr = d.setdefault(check_id, [])
    arr.append(ms)
    if len(arr) > ROLLING_WINDOW:
        arr[:] = arr[-ROLLING_WINDOW:]
    _save_durations(d)


def is_over_budget(check_id: str, ms: int, *, multiplier: float = 5.0) -> tuple[bool, int | None]:
    """Returns (is_over, baseline_median_ms_or_None). Needs >=5 prior samples
    to be meaningful."""
    d = _load_durations()
    arr = d.get(check_id) or []
    if len(arr) < 5:
        return False, None
    baseline = int(median(arr))
    if baseline <= 0:
        return False, None
    return (ms > baseline * multiplier), baseline


def budget_warnings(check_results: list) -> list[str]:
    """Examine a list of CheckResult objects; return a list of human-readable
    warning strings for checks that exceeded their budget."""
    out = []
    for cr in check_results:
        if not hasattr(cr, "duration_ms"):
            continue
        over, baseline = is_over_budget(cr.check_id, cr.duration_ms)
        if over and baseline:
            out.append(
                f"{cr.check_id} took {cr.duration_ms} ms (median is {baseline} ms; "
                f"{cr.duration_ms / baseline:.1f}× over)."
            )
    return out
