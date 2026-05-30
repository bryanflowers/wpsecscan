"""Recent URLs + scan profiles persistence.

Stored under ~/.wpsecscan/:
  - history.json:   last 20 scanned URLs with timestamps
  - profiles.json:  named toggle presets the user saved

Both files are tiny JSON dicts; no schema migration needed yet.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

MAX_HISTORY = 20


def _home() -> Path:
    base = os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _atomic_write_text(path: Path, text: str) -> None:
    """N6 (v2.7.3) — atomic write helper for state files. Concurrent
    scan sessions on history.json / profiles.json / annotations.json /
    comments.json were corrupting each other via bare `write_text`
    (one writer would overwrite the other mid-flush). C13/C15 fixed
    the snapshot path in this same module; this helper covers the
    rest. Pattern: write to a pid-suffixed temp file, then os.replace
    atomically promotes it to the target name.
    """
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _history_path() -> Path:
    return _home() / "history.json"


def _profiles_path() -> Path:
    return _home() / "profiles.json"


# --------------- recent URLs ---------------

def load_history() -> list[dict]:
    """Returns a list of {'url': str, 'last_scanned': float} dicts, newest first."""
    f = _history_path()
    if not f.exists():
        return []
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict) and d.get("url")]
    except (OSError, json.JSONDecodeError):
        pass
    return []


def push_url(url: str) -> None:
    """Record a URL scan; deduped, capped at MAX_HISTORY entries."""
    if not url:
        return
    entries = [e for e in load_history() if e.get("url") != url]
    entries.insert(0, {"url": url, "last_scanned": time.time()})
    entries = entries[:MAX_HISTORY]
    try:
        _atomic_write_text(_history_path(),
                            json.dumps(entries, indent=2))
    except OSError:
        pass


def recent_urls() -> list[str]:
    """Just the URL strings, newest first."""
    return [e["url"] for e in load_history()]


# --------------- scan profiles ---------------

def load_profiles() -> dict[str, dict]:
    """Returns {name: profile-dict}. Profile keys: aggressive, prove, deep_throttle,
    deep_throttle_attempts, deep_throttle_pacing_s, save_reports, auth_user, auth_pass."""
    f = _profiles_path()
    if not f.exists():
        return {}
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if isinstance(v, dict)}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_profile(name: str, profile: dict) -> None:
    if not name:
        return
    profiles = load_profiles()
    # Strip empty creds — don't persist a saved profile that's silently auth'd
    profile = {k: v for k, v in profile.items() if v not in ("", None)}
    profiles[name] = profile
    try:
        _atomic_write_text(_profiles_path(),
                            json.dumps(profiles, indent=2))
    except OSError:
        pass


def delete_profile(name: str) -> None:
    profiles = load_profiles()
    if name in profiles:
        del profiles[name]
        try:
            _atomic_write_text(_profiles_path(),
                                json.dumps(profiles, indent=2))
        except OSError:
            pass


# --------------- prior reports (for diff) ---------------

def _reports_dir() -> Path:
    p = _home() / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe_filename(url: str) -> str:
    import re
    from urllib.parse import urlparse
    host = urlparse(url).hostname or "site"
    return re.sub(r"[^a-z0-9.-]+", "_", host.lower())


def save_report_snapshot(url: str, report_json_text: str) -> None:
    """Persist the latest JSON for a URL. Writes two files plus #62 sigs:
      - `{safe}.json` (canonical "latest", overwritten each run — back-compat)
      - `{safe}-{YYYYmmdd-HHMMSS}.json` (timestamped history for trend / compare)
      - `{safe}-{ts}.json.sig` — HMAC-SHA256 of the JSON, signed with a
                                  per-install secret. verify_snapshot()
                                  recomputes on read to detect tampering.
    Old timestamped snapshots are retained; pruning is the caller's job.
    """
    if not url or not report_json_text:
        return
    from datetime import datetime as _dt, timezone as _tz
    import hmac as _hmac, hashlib as _h
    safe = _safe_filename(url)
    ts = _dt.now(_tz.utc).strftime("%Y%m%d-%H%M%S")
    try:
        d = _reports_dir()
        # C15 (v2.7.2) — write the timestamped snapshot FIRST, then
        # atomically promote the "latest" pointer. Previous order
        # could leave `latest` updated but the snapshot missing if
        # the process was killed between the two writes, making
        # `wpsecscan compare` inconsistent.
        snap_path = d / f"{safe}-{ts}.json"
        snap_path.write_text(report_json_text, encoding="utf-8")
        # #62 — sign the snapshot.
        secret = _snapshot_signing_secret()
        sig = _hmac.new(secret.encode("utf-8"),
                          report_json_text.encode("utf-8"), _h.sha256).hexdigest()
        snap_path.with_suffix(".json.sig").write_text(f"sha256={sig}\n",
                                                          encoding="utf-8")
        # Atomic latest-pointer promotion.
        import os as _os
        latest = d / f"{safe}.json"
        latest_tmp = d / f"{safe}.json.tmp.{_os.getpid()}"
        latest_tmp.write_text(report_json_text, encoding="utf-8")
        _os.replace(latest_tmp, latest)
    except OSError:
        pass


def _snapshot_signing_secret() -> str:
    """Return (and lazily-create) the per-install snapshot signing secret.

    N7 (v2.7.3) — was: plain `write_text` (no 0o600 mode → world-
    readable on POSIX) + TOCTOU on `if p.exists()` (two parallel
    workers race; the loser's secret silently overwrites the winner's,
    invalidating every snapshot signed before the race resolves).
    Now: O_EXCL atomic create with 0o600 mode; on FileExistsError
    read the racing process's secret instead of overwriting it.
    """
    p = _home() / "snapshot-signing-secret.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8")).get("secret", "")
        except (OSError, ValueError):
            pass
    import os as _os
    import secrets as _secrets
    p.parent.mkdir(parents=True, exist_ok=True)
    secret = _secrets.token_hex(32)
    payload = json.dumps({"secret": secret}).encode("utf-8")
    try:
        fd = _os.open(str(p),
                       _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        with _os.fdopen(fd, "wb") as fh:
            fh.write(payload)
    except FileExistsError:
        # Another process won the race; use its secret.
        try:
            return json.loads(p.read_text(encoding="utf-8")).get("secret", "")
        except (OSError, ValueError):
            return secret
    except OSError:
        pass
    return secret


def verify_snapshot(snap_path: Path) -> tuple[bool, str]:
    """#62: verify the HMAC signature for a snapshot file.
    Returns (ok, reason). ok=False when sig missing or mismatched."""
    sig_path = snap_path.with_suffix(".json.sig")
    if not sig_path.exists():
        return False, "no signature file"
    try:
        stored = sig_path.read_text(encoding="utf-8").strip()
        if not stored.startswith("sha256="):
            return False, "malformed signature"
        expected = stored.split("=", 1)[1].strip()
        body = snap_path.read_text(encoding="utf-8")
    except OSError as e:
        return False, str(e)
    import hmac as _hmac, hashlib as _h
    secret = _snapshot_signing_secret()
    actual = _hmac.new(secret.encode("utf-8"), body.encode("utf-8"), _h.sha256).hexdigest()
    if _hmac.compare_digest(expected, actual):
        return True, "ok"
    return False, "signature mismatch (snapshot may have been tampered)"


def previous_report_path(url: str) -> Path | None:
    """Returns the previous-scan JSON path for this URL, or None."""
    p = _reports_dir() / (_safe_filename(url) + ".json")
    return p if p.exists() else None


def snapshot_history(url: str) -> list[Path]:
    """Return all timestamped snapshots for a URL, sorted oldest-to-newest.
    Excludes the canonical `{safe}.json` (the "latest" alias). Used by
    `wpsecscan compare URL` to diff consecutive scans."""
    import glob as _glob
    safe = _safe_filename(url)
    # glob.escape() prevents `.` from being treated as a wildcard, so a
    # rogue file like `example.com-evil.com-...json` can't be matched as a
    # snapshot of `example.com`.
    pattern = f"{_glob.escape(safe)}-*.json"
    return sorted(_reports_dir().glob(pattern))


# --------------- Finding annotations (#3) ---------------
#
# Persisted per-URL: a dict mapping a finding's fingerprint to {status, note, ts}.
# The fingerprint is (check_id, title) — title is stable enough for re-scans,
# and check_id qualifies it so collisions across checks don't merge.

def _annotations_path() -> Path:
    return _home() / "annotations.json"


def load_annotations() -> dict[str, dict]:
    """Returns {url: {fingerprint: {status, note, ts}}}."""
    f = _annotations_path()
    if not f.exists():
        return {}
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_annotations(d: dict) -> None:
    try:
        _atomic_write_text(_annotations_path(),
                            json.dumps(d, indent=2))
    except OSError:
        pass


def annotation_fingerprint(check_id: str, finding_title: str) -> str:
    """Stable key for one finding within a URL's report."""
    return f"{check_id}::{finding_title}"


def get_annotation(url: str, check_id: str, finding_title: str) -> dict | None:
    """Return {status, note, ts} or None if not annotated."""
    return load_annotations().get(url, {}).get(annotation_fingerprint(check_id, finding_title))


def set_annotation(url: str, check_id: str, finding_title: str, status: str,
                   note: str = "", snooze_until: str = "") -> None:
    """status is typically 'accepted-risk', 'false-positive', or '' (clear).

    `snooze_until` accepts an ISO date (YYYY-MM-DD). When set, the
    annotation has an additional `snooze_until` field; consumers should
    treat the finding as suppressed only while today < snooze_until and
    automatically resurface it once the date passes (handled at
    annotation-load time by `is_active_annotation()`).
    """
    d = load_annotations()
    bucket = d.setdefault(url, {})
    fp = annotation_fingerprint(check_id, finding_title)
    if not status:
        bucket.pop(fp, None)
        if not bucket:
            d.pop(url, None)
    else:
        entry: dict = {"status": status, "note": note or "", "ts": time.time()}
        if snooze_until:
            entry["snooze_until"] = snooze_until
        bucket[fp] = entry
    _save_annotations(d)


def is_active_annotation(entry: dict) -> bool:
    """Return False if a snoozed annotation has expired (the finding should
    resurface). Returns True for non-snoozed and not-yet-expired entries."""
    if not isinstance(entry, dict):
        return False
    snooze = entry.get("snooze_until")
    if not snooze:
        return True
    try:
        from datetime import date
        return date.today() < date.fromisoformat(snooze)
    except (ValueError, TypeError):
        return True


# --------------- G1 Finding ownership ---------------
#
# Same fingerprint scheme as annotations — stored separately so a finding
# can be both "assigned to X" and "marked accepted-risk".

def set_assignee(url: str, check_id: str, finding_title: str, assignee: str) -> None:
    """G1: tag a finding with an owner (free-form text; usually a name or email).
    Empty string clears the assignment."""
    d = load_annotations()
    bucket = d.setdefault(url, {})
    fp = annotation_fingerprint(check_id, finding_title)
    entry = bucket.get(fp) or {}
    if assignee:
        entry["assigned_to"] = assignee
        entry["assigned_ts"] = time.time()
    else:
        entry.pop("assigned_to", None)
        entry.pop("assigned_ts", None)
    if entry:
        bucket[fp] = entry
    else:
        bucket.pop(fp, None)
        if not bucket:
            d.pop(url, None)
    _save_annotations(d)


def get_assignee(url: str, check_id: str, finding_title: str) -> str | None:
    entry = get_annotation(url, check_id, finding_title) or {}
    return entry.get("assigned_to") or None


# --------------- G2 Comment threads ---------------
#
# Lives in ~/.wpsecscan/comments.json: {url: {fingerprint: [{author, body, ts}, ...]}}

def _comments_path() -> Path:
    return _home() / "comments.json"


def load_comments() -> dict[str, dict[str, list[dict]]]:
    f = _comments_path()
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save_comments(d: dict) -> None:
    try:
        _atomic_write_text(_comments_path(),
                            json.dumps(d, indent=2))
    except OSError:
        pass


def add_comment(url: str, check_id: str, finding_title: str, author: str, body: str) -> None:
    if not body.strip():
        return
    d = load_comments()
    bucket = d.setdefault(url, {})
    fp = annotation_fingerprint(check_id, finding_title)
    thread = bucket.setdefault(fp, [])
    thread.append({
        "author": (author or "anonymous").strip()[:64],
        "body": body.strip()[:4000],
        "ts": time.time(),
    })
    _save_comments(d)


def get_comments(url: str, check_id: str, finding_title: str) -> list[dict]:
    return load_comments().get(url, {}).get(annotation_fingerprint(check_id, finding_title), [])


def delete_comment(url: str, check_id: str, finding_title: str, index: int) -> bool:
    """Delete the comment at the given 0-based index. Returns True if a comment was removed."""
    d = load_comments()
    fp = annotation_fingerprint(check_id, finding_title)
    bucket = d.get(url, {})
    thread = bucket.get(fp, [])
    if 0 <= index < len(thread):
        del thread[index]
        if not thread:
            bucket.pop(fp, None)
            if not bucket:
                d.pop(url, None)
        _save_comments(d)
        return True
    return False
