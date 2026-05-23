"""Round-56 activity event bus.

Every feature that does meaningful work — threat-intel lookups, reporter
writes, audit shipping, screenshots, auto-disable, etc. — emits a tiny event
to this in-process bus. The CLI live dashboard and the GUI activity-feed
pane subscribe and render the events in real time.

The bus is intentionally trivial: a bounded deque + a list of callbacks +
a lock. No async, no IPC, no persistence. Subscribers that raise are
swallowed so a broken consumer can't kill a scan.

Usage:
    from . import activity
    activity.emit("threat_intel", "KEV: 3 CVEs enriched")
    activity.emit("reporter", "HTML: report.html (47 KB)", extra_kb=47)
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable

# Categories → badge colors (used by console_live + GUI activity feed).
# Add new categories sparingly; consumers may not know about them.
CATEGORY_COLORS = {
    "threat_intel": "yellow",
    "reporter":     "blue",
    "integration":  "magenta",
    "governance":   "cyan",
    "meta":         "orange",
    "artifact":     "green",
    "check":        "white",
}

_MAX_EVENTS = 200
_events: "deque[dict]" = deque(maxlen=_MAX_EVENTS)
_subscribers: list[Callable[[dict], None]] = []
_lock = threading.Lock()


def emit(category: str, message: str, **extra: Any) -> None:
    """Fire-and-forget. Never raises. Cheap to call from anywhere."""
    event = {
        "ts": time.time(),
        "category": category,
        "message": str(message)[:300],  # cap text so a runaway message can't OOM
    }
    if extra:
        event["extra"] = extra
    with _lock:
        _events.append(event)
        # Snapshot subscribers so callbacks can't see partial mutations if one
        # of them calls subscribe()/unsubscribe() during dispatch.
        subs = list(_subscribers)
    for cb in subs:
        try:
            cb(event)
        except Exception:  # noqa: BLE001 — a broken subscriber must not break the scan
            pass


def subscribe(callback: Callable[[dict], None]) -> None:
    """Register a callback. Called synchronously after every emit()."""
    with _lock:
        if callback not in _subscribers:
            _subscribers.append(callback)


def unsubscribe(callback: Callable[[dict], None]) -> None:
    with _lock:
        try:
            _subscribers.remove(callback)
        except ValueError:
            pass


def recent(n: int = 50) -> list[dict]:
    """Return the most recent `n` events (oldest first)."""
    with _lock:
        if n >= len(_events):
            return list(_events)
        # deque doesn't slice; islice avoids copying the whole buffer
        from itertools import islice
        start = len(_events) - n
        return list(islice(_events, start, len(_events)))


def clear() -> None:
    """Drop all buffered events. Call between batch-mode scans so each
    target's stats panel reflects only its own activity."""
    with _lock:
        _events.clear()


def to_list() -> list[dict]:
    """Snapshot the full buffer. Used by json_out.py to embed `activity_log`
    in the saved report so a diff-viewer replay can show the live timeline."""
    with _lock:
        return list(_events)


def counts_by_category() -> dict[str, int]:
    """Aggregate counts — used by the end-of-scan stats panel."""
    out: dict[str, int] = {}
    with _lock:
        for e in _events:
            cat = e.get("category", "?")
            out[cat] = out.get(cat, 0) + 1
    return out


def events_by_category(category: str) -> list[dict]:
    """Filter to one category — used by the stats panel for per-section detail."""
    with _lock:
        return [e for e in _events if e.get("category") == category]
