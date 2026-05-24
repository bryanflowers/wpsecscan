"""Round-60 — bug-report + crash-report system.

Wraps the existing crash_submit module and adds:

  - System-info gathering (OS, Python, WPSecScan version, recent checks)
  - Free-text feedback + repro fields for the GUI "Report Bug" dialog
  - Optional GlitchTip / Sentry-protocol crash POST (opt-in via env var)
  - List of prior crash-*.txt files with submitted/dismissed state
  - One-stop builder for either:
       * pre-filled GH Issues URL (no network from the scanner)
       * direct POST to GlitchTip (when DSN is configured)

Privacy: every body sent over the network is passed through
crash_submit.redact() first AND wpsecscan.ai_safety.mask_private() if
available. Nothing leaves the machine without an explicit user action
(open browser) or an explicit env var (WPSECSCAN_GLITCHTIP_DSN).
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError

from . import __version__
from . import crash_submit


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


# ---- System info ----

def system_info() -> dict:
    """Tidy dict suitable for inclusion in any bug report body."""
    return {
        "wpsecscan_version": __version__,
        "python_version":    sys.version.split(" ", 1)[0],
        "os":                f"{platform.system()} {platform.release()}",
        "os_full":           platform.platform(),
        "machine":           platform.machine(),
        "exe":               sys.argv[0] if sys.argv else "?",
        "frozen":            getattr(sys, "frozen", False),
        "tz":                time.strftime("%z"),
    }


def _sanitise(text: str) -> str:
    """Run crash_submit.redact + ai_safety.mask_private when available."""
    out = crash_submit.redact(text or "")
    try:
        from . import ai_safety
        out = ai_safety.mask_private(out)
    except ImportError:
        pass
    return out


# ---- GH Issues pre-fill ----

def build_github_issue_url(*, title: str, repro: str = "", include_log: str = "",
                              include_report_path: str | None = None,
                              labels: str = "bug") -> str:
    """Build a GH-Issues-new URL with system info + free-text + optional log/report."""
    info = system_info()
    body_lines = [
        "## Environment",
        "",
        f"- WPSecScan **{info['wpsecscan_version']}**",
        f"- Python {info['python_version']}",
        f"- {info['os']}  (`{info['machine']}`)",
        f"- frozen .exe: {info['frozen']}",
        "",
        "## Repro / what I was doing",
        "",
        (repro or "_(please describe)_"),
        "",
    ]
    if include_log:
        body_lines.extend(["## Log excerpt (redacted)", "", "```", _sanitise(include_log[-4000:]), "```", ""])
    if include_report_path:
        try:
            rep = Path(include_report_path).read_text(encoding="utf-8", errors="replace")
            body_lines.extend(["## Report excerpt (redacted)", "", "```json",
                                 _sanitise(rep[:2000]), "```", ""])
        except OSError:
            pass
    body_lines.append("_Submitted via the in-app bug-report helper._")
    params = urllib.parse.urlencode({
        "title": title or f"[Bug] WPSecScan v{info['wpsecscan_version']}",
        "body": "\n".join(body_lines),
        "labels": labels,
    })
    return f"https://github.com/{crash_submit.REPO}/issues/new?{params}"


# ---- Opt-in GlitchTip / Sentry POST ----

def _parse_dsn(dsn: str) -> dict | None:
    """Parse a Sentry-protocol DSN into {host, project_id, public_key}."""
    if not dsn or "://" not in dsn:
        return None
    try:
        scheme, rest = dsn.split("://", 1)
        creds, host_path = rest.split("@", 1)
        public_key = creds.split(":", 1)[0]
        host, project_id = host_path.rsplit("/", 1)
        return {"scheme": scheme, "host": host, "project_id": project_id,
                 "public_key": public_key}
    except (ValueError, IndexError):
        return None


def submit_to_glitchtip(crash_log_path: Path | None = None, *,
                          extra: dict | None = None,
                          dsn: str | None = None) -> bool:
    """POST a Sentry-format event to GlitchTip / Sentry. Returns True on 2xx.

    Disabled unless WPSECSCAN_GLITCHTIP_DSN is set (or `dsn` arg passed).
    Never raises.
    """
    dsn = dsn or os.environ.get("WPSECSCAN_GLITCHTIP_DSN", "")
    parsed = _parse_dsn(dsn)
    if not parsed:
        return False
    log_text = ""
    if crash_log_path and crash_log_path.exists() and not crash_log_path.is_symlink():
        try:
            log_text = crash_log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    log_text = _sanitise(log_text)[-8000:]

    event = {
        "event_id": os.urandom(16).hex(),
        "timestamp": time.time(),
        "platform": "python",
        "level": "error",
        "logger": "wpsecscan",
        "release": f"wpsecscan@{__version__}",
        "environment": "prod" if getattr(sys, "frozen", False) else "dev",
        "tags": system_info(),
        "extra": {"crash_log": log_text, **(extra or {})},
        "message": {"formatted": (log_text.splitlines()[-1] if log_text else "WPSecScan event")},
    }
    url = f"{parsed['scheme']}://{parsed['host']}/api/{parsed['project_id']}/store/"
    sentry_auth = (
        f"Sentry sentry_version=7, sentry_client=wpsecscan/{__version__}, "
        f"sentry_key={parsed['public_key']}"
    )
    req = urllib.request.Request(
        url, data=json.dumps(event).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                  "X-Sentry-Auth": sentry_auth,
                  "User-Agent": f"WPSecScan/{__version__} (bug_report)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status < 300
    except (HTTPError, URLError, OSError, ValueError):
        return False


# ---- Prior crash list ----

def list_prior_crashes() -> list[dict]:
    """Return one entry per crash-*.txt in ~/.wpsecscan/, sorted newest first.
    Each entry: {path, ts, size, status} where status is read from a sidecar
    `.status` file (submitted/dismissed/unread)."""
    out = []
    for p in sorted(_home().glob("crash-*.txt"), reverse=True):
        if p.is_symlink():
            continue
        status_path = p.with_suffix(".status")
        status = "unread"
        if status_path.exists() and not status_path.is_symlink():
            try:
                status = status_path.read_text(encoding="utf-8").strip()[:16] or "unread"
            except OSError:
                pass
        try:
            stat = p.stat()
            out.append({"path": str(p), "ts": int(stat.st_mtime),
                          "size": stat.st_size, "status": status})
        except OSError:
            continue
    return out


def mark_crash_status(crash_path: Path | str, status: str) -> None:
    """Persist a status alongside the crash file. Accepted: submitted, dismissed."""
    if status not in ("submitted", "dismissed", "unread"):
        return
    p = Path(crash_path)
    sp = p.with_suffix(".status")
    if sp.is_symlink():
        try:
            sp.unlink()
        except OSError:
            return
    try:
        sp.write_text(status, encoding="utf-8")
    except OSError:
        pass


def unread_crash_count() -> int:
    return sum(1 for c in list_prior_crashes() if c["status"] == "unread")


# ---- Feedback (non-crash) ----

def send_feedback(*, message: str, category: str = "general") -> str:
    """Build a GH-issue URL for non-crash feedback ('wrong finding', 'missing feature').
    `category` becomes a GH label so triage is easy."""
    label = "feedback," + {
        "wrong_finding": "false-positive",
        "missing_feature": "enhancement",
        "general": "feedback",
    }.get(category, "feedback")
    title = f"[Feedback] {message[:60]}{'…' if len(message) > 60 else ''}"
    return build_github_issue_url(title=title, repro=message, labels=label)
