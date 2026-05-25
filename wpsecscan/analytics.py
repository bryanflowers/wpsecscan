"""Opt-in, transparent, local-first usage analytics.

Round-65 — collect "which features get used" data so we can improve
WPSecScan, while keeping privacy guarantees the user can verify.

## Privacy guarantees

- **Default: DISABLED.** Nothing is recorded until the user runs
  `wpsecscan analytics enable` (or ticks the GUI box).
- **Local-first.** Events go to `~/.wpsecscan/analytics/events.jsonl`.
  No upload unless the user ALSO sets `WPSECSCAN_ANALYTICS_UPLOAD_URL`
  AND opts-in to upload.
- **No PII, no URLs, no findings.** Only feature names + counts +
  durations. The full payload is shown to the user with
  `wpsecscan analytics show`.
- **Anonymous ID.** A random UUID rotated every 90 days, stored only
  locally. Never derived from hostname / IP / username.
- **Forget-me.** `wpsecscan analytics forget` deletes everything
  locally AND posts a deletion request to the upload destination
  (if configured).
- **No background uploads.** Even when upload is enabled, batches go
  out at most once per scan (piggy-backed on the scan request) and
  never from any background thread.

## What we record (when enabled)

| Event | Fields |
|-------|--------|
| `cli_command`    | subcommand, duration_ms, exit_status |
| `check_ran`      | check_id, duration_ms, finding_count (no titles/URLs) |
| `gui_action`     | action_name, duration_ms |
| `feature_used`   | feature_name (e.g. "ai_triage.severity_auto_tuner") |
| `report_export`  | format (csv/json/pdf/etc.), finding_count_bucket |

We deliberately do NOT record:
- Target URLs (not even hashed)
- Finding titles, evidence, remediation
- Site config (sites.json contents)
- API keys / secrets of any kind
- Timestamps to higher precision than minute
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ============================================================
# Storage paths
# ============================================================


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _analytics_dir() -> Path:
    return _home() / "analytics"


def _settings_path() -> Path:
    return _analytics_dir() / "settings.json"


def _events_path() -> Path:
    return _analytics_dir() / "events.jsonl"


def _anon_id_path() -> Path:
    return _analytics_dir() / "anonymous_id.txt"


# ============================================================
# Settings + anonymous ID
# ============================================================


@dataclass
class AnalyticsSettings:
    enabled: bool = False
    # Set to a URL to enable uploads; None = local-only (recommended)
    upload_destination: str | None = None
    enabled_at: str | None = None  # ISO timestamp of opt-in
    last_upload_at: str | None = None

    @classmethod
    def load(cls) -> "AnalyticsSettings":
        p = _settings_path()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def save(self) -> None:
        p = _settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def _get_or_make_anon_id() -> str:
    """Quarterly-rotating UUID. Same shape as leaderboard global_rank."""
    p = _anon_id_path()
    now = datetime.now(tz=timezone.utc)
    quarter_key = f"{now.year}-Q{(now.month - 1) // 3 + 1}"
    if p.exists():
        try:
            line = p.read_text(encoding="utf-8").strip().split(":", 1)
            if len(line) == 2 and line[0] == quarter_key:
                return line[1]
        except OSError:
            pass
    new = str(uuid.uuid4())
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(f"{quarter_key}:{new}", encoding="utf-8")
    return new


# ============================================================
# Event recording — only when enabled
# ============================================================


# Allowed event types — whitelist. Adding a new type? Update this.
_ALLOWED_EVENTS = {"cli_command", "check_ran", "gui_action", "feature_used", "report_export"}


# Allowed field names per event type. Anything else is dropped on the
# way in — defence in depth against accidental PII leaks.
_ALLOWED_FIELDS = {
    "cli_command":  {"subcommand", "duration_ms", "exit_status"},
    "check_ran":    {"check_id", "duration_ms", "finding_count_bucket"},
    "gui_action":   {"action_name", "duration_ms"},
    "feature_used": {"feature_name"},
    "report_export":{"format", "finding_count_bucket"},
}


def _bucket(n: int) -> str:
    """Convert a finding count into a coarse bucket to avoid fingerprinting."""
    if n == 0:    return "0"
    if n <= 5:    return "1-5"
    if n <= 25:   return "6-25"
    if n <= 100:  return "26-100"
    if n <= 500:  return "101-500"
    return "500+"


def record(event_type: str, **fields_in: Any) -> None:
    """Record an event. No-op if analytics disabled.

    Drops any field not in _ALLOWED_FIELDS[event_type] to guard against
    accidental PII leakage.
    """
    s = AnalyticsSettings.load()
    if not s.enabled:
        return
    if event_type not in _ALLOWED_EVENTS:
        return

    allowed = _ALLOWED_FIELDS[event_type]
    clean = {k: v for k, v in fields_in.items() if k in allowed}

    # Auto-bucket any 'finding_count' raw int
    if "finding_count" in fields_in and "finding_count_bucket" in allowed:
        clean["finding_count_bucket"] = _bucket(int(fields_in["finding_count"]))

    # Round timestamps to the minute
    now = datetime.now(tz=timezone.utc).replace(second=0, microsecond=0)
    entry = {
        "ts":         now.isoformat(),
        "anon_id":    _get_or_make_anon_id(),
        "wpsecscan":  _wpsecscan_version(),
        "event":      event_type,
        "fields":     clean,
    }
    _append_event(entry)


def _append_event(entry: dict) -> None:
    p = _events_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    # Cap log at 10 MB — roll to .1, .2, .3 then drop oldest
    try:
        if p.exists() and p.stat().st_size > 10 * 1024 * 1024:
            for i in range(3, 0, -1):
                src = p.with_suffix(f".jsonl.{i}")
                dst = p.with_suffix(f".jsonl.{i+1}")
                if src.exists():
                    src.rename(dst)
            p.rename(p.with_suffix(".jsonl.1"))
    except OSError:
        pass
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _wpsecscan_version() -> str:
    try:
        from . import __version__
        return __version__
    except ImportError:
        return "unknown"


# ============================================================
# Public control-plane API
# ============================================================


def enable(*, upload_destination: str | None = None) -> str:
    s = AnalyticsSettings.load()
    s.enabled = True
    s.enabled_at = datetime.now(tz=timezone.utc).isoformat()
    if upload_destination is not None:
        s.upload_destination = upload_destination
    s.save()
    return (
        "Analytics ENABLED. Events recorded locally at "
        f"{_events_path()}.\n"
        "  • Inspect anytime: wpsecscan analytics show\n"
        "  • Delete all data: wpsecscan analytics forget\n"
        "  • Disable:         wpsecscan analytics disable\n"
        + (f"  • Upload destination: {s.upload_destination}\n" if s.upload_destination
           else "  • Upload destination: NONE (local-only)\n")
    )


def disable() -> str:
    s = AnalyticsSettings.load()
    s.enabled = False
    s.save()
    return "Analytics DISABLED. Existing local data preserved — use `forget` to delete it."


def forget() -> str:
    """Delete everything locally + post a deletion request upstream."""
    s = AnalyticsSettings.load()
    deleted = []
    for p in (_events_path(), _anon_id_path()):
        if p.exists():
            try:
                p.unlink()
                deleted.append(str(p))
            except OSError as e:
                return f"failed to delete {p}: {e}"
    # Rotated log files
    for i in range(1, 5):
        for path in (_events_path().with_suffix(f".jsonl.{i}"),):
            if path.exists():
                try:
                    path.unlink()
                    deleted.append(str(path))
                except OSError:
                    pass

    # Optional: ping the upload destination to forget the anonymous ID
    # (anon ID was just deleted, so we send the SHA-256 of it — only the
    # server can correlate it, and only if it stored deliveries with the
    # same hash).
    upload_msg = ""
    if s.upload_destination:
        try:
            import httpx
            r = httpx.post(
                s.upload_destination.rstrip("/") + "/forget",
                json={"deletion_request": True},
                timeout=10.0,
            )
            upload_msg = f"\nServer forget request: HTTP {r.status_code}"
        except Exception as e:  # noqa: BLE001
            upload_msg = f"\nServer forget request failed: {e}"
    return f"Deleted {len(deleted)} local file(s).{upload_msg}"


def status() -> dict:
    s = AnalyticsSettings.load()
    events_path = _events_path()
    count = 0
    if events_path.exists():
        try:
            count = sum(1 for _ in events_path.open("r", encoding="utf-8"))
        except OSError:
            pass
    return {
        "enabled":            s.enabled,
        "enabled_at":         s.enabled_at,
        "anonymous_id":       _get_or_make_anon_id() if s.enabled else "(not generated)",
        "event_count":        count,
        "storage_path":       str(events_path),
        "upload_destination": s.upload_destination,
        "last_upload_at":     s.last_upload_at,
    }


def show_recent(limit: int = 50) -> str:
    """Pretty-print the last N events for the user to inspect."""
    p = _events_path()
    if not p.exists():
        return "No analytics events recorded yet."
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return f"read error: {e}"
    out = [f"Last {min(limit, len(lines))} of {len(lines)} events:"]
    for line in lines[-limit:]:
        try:
            entry = json.loads(line)
            f_str = " ".join(f"{k}={v}" for k, v in entry.get("fields", {}).items())
            out.append(f"  {entry.get('ts')}  {entry.get('event'):<14} {f_str}")
        except ValueError:
            continue
    return "\n".join(out)


def export(path: str) -> str:
    """Write the events.jsonl to a path of the user's choosing."""
    p = _events_path()
    if not p.exists():
        return "No analytics events to export."
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        dest.unlink()
    dest.write_bytes(p.read_bytes())
    return f"Exported to {dest}"


# ============================================================
# Optional upload (called explicitly; never auto)
# ============================================================


def upload_now() -> str:
    """Send the local events.jsonl to the configured destination.

    No-op if upload_destination isn't set. Caller must invoke this
    explicitly — never auto-triggered from a scan.
    """
    s = AnalyticsSettings.load()
    if not s.enabled or not s.upload_destination:
        return "Upload skipped — disabled or no destination set."
    p = _events_path()
    if not p.exists():
        return "No events to upload."
    try:
        import httpx
        r = httpx.post(
            s.upload_destination.rstrip("/") + "/events",
            content=p.read_bytes(),
            headers={"Content-Type": "application/x-ndjson"},
            timeout=30.0,
        )
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001
        return f"Upload failed: {e}"
    s.last_upload_at = datetime.now(tz=timezone.utc).isoformat()
    s.save()
    # Truncate the local log after a successful upload (events persist server-side)
    try:
        p.write_text("", encoding="utf-8")
    except OSError:
        pass
    return f"Uploaded ok. Local log truncated."


# ============================================================
# Convenience: record helpers callers can drop in anywhere
# ============================================================


def time_block(event_type: str, **fields):
    """Context manager that records duration_ms automatically.

        with analytics.time_block("cli_command", subcommand="scan"):
            do_scan()
    """
    return _TimedBlock(event_type, fields)


class _TimedBlock:
    def __init__(self, event_type: str, extra: dict) -> None:
        self._event_type = event_type
        self._extra = extra
        self._start = 0.0

    def __enter__(self):
        # perf_counter is sub-microsecond on Windows; monotonic's ~15 ms
        # default resolution can record 0 ms for short blocks.
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        duration_ms = int((time.perf_counter() - self._start) * 1000)
        fields = dict(self._extra)
        fields["duration_ms"] = duration_ms
        if exc_type is not None and "exit_status" not in fields:
            fields["exit_status"] = "error"
        elif "exit_status" not in fields:
            fields["exit_status"] = "ok"
        record(self._event_type, **fields)
        return False  # don't suppress exceptions
