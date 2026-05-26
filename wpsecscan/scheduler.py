"""Item #73 — cron-syntax scheduler for absolute-time recurring scans.

The existing `watch` daemon delta-watches a fixed set of sites every N
seconds; this scheduler runs scans at *cron-style absolute times*
(\"every Tuesday 03:00\", \"first of the month at midnight\"). Each entry
is a (cron_expr, target, flags) tuple stored in
~/.wpsecscan/cron-schedule.json. The accompanying
`wpsecscan schedule run` daemon evaluates the file once a minute.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _store() -> Path:
    return _home() / "cron-schedule.json"


@dataclass
class CronEntry:
    """One scheduled scan. cron_expr is 5-field POSIX cron syntax
    (minute hour day_of_month month day_of_week)."""
    cron_expr: str
    target: str
    flags: list[str] = field(default_factory=list)
    name: str = ""
    enabled: bool = True
    last_run: int = 0


def _load() -> list[CronEntry]:
    p = _store()
    if not p.exists():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8")) or []
    except (OSError, ValueError):
        return []
    out = []
    for e in raw:
        out.append(CronEntry(
            cron_expr=e.get("cron_expr", ""),
            target=e.get("target", ""),
            flags=list(e.get("flags") or []),
            name=e.get("name", ""),
            enabled=bool(e.get("enabled", True)),
            last_run=int(e.get("last_run", 0)),
        ))
    return out


def _save(entries: list[CronEntry]) -> None:
    p = _store()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([asdict(e) for e in entries], indent=2),
                  encoding="utf-8")


# ---------------------------------------------------------------------------
# Cron evaluation
# ---------------------------------------------------------------------------

def _parse_field(field_expr: str, lo: int, hi: int) -> set[int]:
    """Parse one cron field. Supports '*', 'N', 'N,M', 'L-H', '*/STEP', 'L-H/STEP'."""
    out: set[int] = set()
    for part in field_expr.split(","):
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            step = max(1, int(step_s))
        if part == "*":
            lo_p, hi_p = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            lo_p, hi_p = int(a), int(b)
        else:
            lo_p = hi_p = int(part)
        for v in range(lo_p, hi_p + 1, step):
            if lo <= v <= hi:
                out.add(v)
    return out


def matches(cron_expr: str, when: datetime) -> bool:
    """Return True if the given datetime matches the cron expression."""
    try:
        fields = cron_expr.split()
        if len(fields) != 5:
            return False
        mins = _parse_field(fields[0], 0, 59)
        hrs  = _parse_field(fields[1], 0, 23)
        dom  = _parse_field(fields[2], 1, 31)
        mon  = _parse_field(fields[3], 1, 12)
        dow  = _parse_field(fields[4], 0, 6)
    except (ValueError, IndexError):
        return False
    return (when.minute in mins and when.hour in hrs
            and when.day in dom and when.month in mon
            and when.weekday() in dow)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def add(cron_expr: str, target: str, flags: list[str] | None = None,
         name: str = "") -> CronEntry:
    entries = _load()
    entry = CronEntry(cron_expr=cron_expr, target=target,
                       flags=list(flags or []), name=name or target)
    entries.append(entry)
    _save(entries)
    return entry


def remove(idx_or_name: str) -> bool:
    entries = _load()
    n = len(entries)
    if idx_or_name.isdigit():
        i = int(idx_or_name)
        if 0 <= i < len(entries):
            entries.pop(i)
    else:
        entries = [e for e in entries if e.name != idx_or_name]
    _save(entries)
    return len(entries) < n


def list_entries() -> list[CronEntry]:
    return _load()


def run_once(now: datetime | None = None) -> list[tuple[CronEntry, int]]:
    """Evaluate every entry once; trigger scans for matches. Returns
    [(entry, exit_code), …]. Intended for the daemon loop."""
    now = now or datetime.now().replace(second=0, microsecond=0)
    entries = _load()
    triggered: list[tuple[CronEntry, int]] = []
    for entry in entries:
        if not entry.enabled or not matches(entry.cron_expr, now):
            continue
        # Don't double-fire within the same minute (e.g. if the loop ticks
        # twice for clock-skew reasons).
        if entry.last_run and int(now.timestamp()) - entry.last_run < 50:
            continue
        cmd = [sys.executable, "-m", "wpsecscan", entry.target, *entry.flags]
        try:
            rc = subprocess.run(cmd, capture_output=True, timeout=3600).returncode
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"[scheduler] {entry.name}: {e}", file=sys.stderr)
            rc = -1
        entry.last_run = int(now.timestamp())
        triggered.append((entry, rc))
    if triggered:
        _save(entries)
    return triggered


def daemon_loop() -> None:
    """Tick once a minute, dispatch matching entries. Ctrl+C to stop."""
    print("[scheduler] daemon started — Ctrl+C to stop")
    while True:
        try:
            now = datetime.now().replace(second=0, microsecond=0)
            results = run_once(now)
            for entry, rc in results:
                print(f"[scheduler] {now.isoformat()}  ran {entry.name!r} → exit {rc}")
            # Sleep until the next minute boundary.
            time.sleep(max(1.0, 60 - datetime.now().second))
        except KeyboardInterrupt:
            print("\n[scheduler] stopped"); return
