"""Item #74 — finding-level SLA tracker.

Each finding's first-seen and last-seen timestamps are persisted across
scans so the operator can answer: "Critical X has been open for 47
days." The implementation reads snapshot_history (already maintained by
every scan) and walks back through the saved JSON snapshots to assemble
a per-finding ledger.

Finding identity is (check_id, finding_title) — same dedup key the
issue-tracker push uses. We don't try to match by URL because many
findings are site-wide.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable


def _safe_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00").split("+", 1)[0])
    except (ValueError, AttributeError):
        return None


def build_ledger(snapshot_files: Iterable[Path]) -> dict[tuple[str, str], dict]:
    """Walk snapshots chronologically and return:

        { (check_id, title): {
              first_seen: ISO,
              last_seen: ISO,
              seen_count: int,
              currently_open: bool,
              last_severity: str,
          }, ... }

    `currently_open` is True if the finding appears in the most-recent
    snapshot.
    """
    ordered = sorted(snapshot_files, key=lambda p: p.name)
    ledger: dict[tuple[str, str], dict] = {}
    last_snapshot_keys: set[tuple[str, str]] = set()
    for snap in ordered:
        try:
            data = json.loads(snap.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        scan_ts = data.get("scanned_at", "")
        snap_keys: set[tuple[str, str]] = set()
        for result in data.get("results", []):
            cid = result.get("check_id", "")
            for f in result.get("findings", []):
                key = (cid, f.get("title", ""))
                snap_keys.add(key)
                entry = ledger.get(key)
                if entry is None:
                    ledger[key] = {
                        "first_seen": scan_ts,
                        "last_seen": scan_ts,
                        "seen_count": 1,
                        "last_severity": f.get("severity", ""),
                    }
                else:
                    entry["last_seen"] = scan_ts
                    entry["seen_count"] = entry["seen_count"] + 1
                    entry["last_severity"] = f.get("severity", entry["last_severity"])
        last_snapshot_keys = snap_keys

    # Mark currently_open against the LAST snapshot
    for key, entry in ledger.items():
        entry["currently_open"] = key in last_snapshot_keys
    return ledger


def days_open(entry: dict, now: datetime | None = None) -> int | None:
    """Return integer days between first_seen and last_seen (or now)."""
    now = now or datetime.now()
    first = _safe_dt(entry.get("first_seen", ""))
    last = _safe_dt(entry.get("last_seen", ""))
    if first is None:
        return None
    end = last if last is not None else now
    return max(0, (end - first).days)


def sla_breached(entry: dict, sla_days: dict[str, int]) -> bool:
    """Return True if the finding is currently open AND its open-days
    exceed the SLA for its severity. `sla_days` example:
       {\"critical\": 7, \"high\": 30, \"medium\": 60, \"low\": 90}
    """
    if not entry.get("currently_open"):
        return False
    sev = entry.get("last_severity", "")
    sla = sla_days.get(sev)
    if not sla:
        return False
    d = days_open(entry)
    return d is not None and d > sla


def for_target(target: str, sla_days: dict[str, int] | None = None) -> dict:
    """Convenience: build a ledger for the given target URL and return
    {ledger, breached, summary}."""
    from . import history as _h
    snaps = _h.snapshot_history(target)
    ledger = build_ledger(snaps)
    sla_days = sla_days or {"critical": 7, "high": 30, "medium": 60, "low": 90}
    breached = []
    for (cid, title), entry in ledger.items():
        if sla_breached(entry, sla_days):
            breached.append({
                "check_id": cid, "title": title,
                "severity": entry["last_severity"],
                "first_seen": entry["first_seen"],
                "days_open": days_open(entry),
            })
    breached.sort(key=lambda r: r["days_open"], reverse=True)
    return {
        "target": target,
        "ledger": ledger,
        "breached": breached,
        "summary": {
            "tracked": len(ledger),
            "open": sum(1 for e in ledger.values() if e["currently_open"]),
            "breached": len(breached),
        },
    }
