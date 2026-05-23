"""G3 audit log — append-only JSONL of who-ran-what-when.

Every scan invocation writes one line to ~/.wpsecscan/audit.log.jsonl with:
  - timestamp (ISO 8601 UTC)
  - target URL
  - run mode (passive / aggressive / authenticated / deep-throttle)
  - user (from getpass.getuser())
  - host (from socket.gethostname())
  - cli flags (sanitized — passwords stripped)
  - risk score + summary counts (filled after the scan completes)

Used for compliance / forensics ("who ran which scan on $date").
"""
from __future__ import annotations

import getpass
import json
import socket
from datetime import datetime, timezone
from pathlib import Path


def _log_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "audit.log.jsonl"


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except OSError:
        return "(unknown)"


def _safe_host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "(unknown)"


def _scrub_args(args_dict: dict) -> dict:
    """Strip secret-bearing keys from the args record."""
    SECRET_KEYS = {
        "auth_pass", "wpscan_token", "hibp_token", "patchstack_token",
        "abuseipdb_token", "github_search_token", "vt_token",
        "webhook_url", "github_token",
    }
    return {k: ("<redacted>" if k in SECRET_KEYS and v else v) for k, v in args_dict.items()}


def record_scan_start(target: str, args_dict: dict | None = None) -> dict:
    """Write the 'scan started' entry. Returns the partial record (caller passes back to record_scan_done)."""
    rec = {
        "event": "scan_started",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "user": _safe_user(),
        "host": _safe_host(),
        "args": _scrub_args(args_dict or {}),
    }
    try:
        with _log_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass
    try:
        from . import activity as _act
        _act.emit("integration", f"audit log: scan started → {target}")
    except ImportError:
        pass
    return rec


def record_scan_done(target: str, report=None, started_rec: dict | None = None) -> None:
    """Write the 'scan completed' entry with summary + risk score."""
    rec = {
        "event": "scan_completed",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "user": _safe_user(),
        "host": _safe_host(),
    }
    if report is not None:
        try:
            rec["risk_score"] = int(report.risk_score)
            rec["summary"] = report.summary
            rec["duration_ms"] = report.duration_ms
        except (AttributeError, TypeError, ValueError):
            pass
    if started_rec:
        rec["started_at"] = started_rec.get("timestamp_utc")
    try:
        with _log_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass
    try:
        from . import activity as _act
        score = rec.get("risk_score", "?")
        _act.emit("integration", f"audit log: scan complete · risk {score}")
    except ImportError:
        pass


def read_log(limit: int | None = None) -> list[dict]:
    """Return the log entries, newest first. Limit truncates."""
    p = _log_path()
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except (ValueError, json.JSONDecodeError):
            continue
        if limit and len(out) >= limit:
            break
    return out
