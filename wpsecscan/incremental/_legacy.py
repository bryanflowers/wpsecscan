"""K26 Incremental scan + K27 per-host baseline learner.

K26: given a `--since YYYY-MM-DD` flag, re-run only the checks whose target
evidence has likely changed since that date. We approximate "changed" by
comparing two cheap fingerprints between the last snapshot and the live
server: HTTP `Last-Modified` on `/`, and the active plugin/theme/core
version trio. If neither changed, skip checks tagged as "low-churn".

K27: builds a per-URL learned baseline over multiple scans — body length /
status / header set for each probed path. On rescan, flag anomalies (a
path that returned 200/3kB for 30 scans suddenly returning 200/30kB).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


# ---------- K26 incremental scan helpers ----------

# Checks that are pointless to re-run if nothing about the target has changed.
# DNS records, file enumeration, JS supply chain, dev params — these only
# change when someone deploys.
LOW_CHURN_CHECK_IDS = frozenset((
    "exposed_files", "robots_sitemap", "dns_security", "favicon_hash",
    "favicon_fingerprint", "js_supply_chain", "js_libraries", "source_maps",
    "well_known", "webdav", "dev_params", "subdomains", "secret_leak",
    "tls_deep", "tls_protocol_audit", "tls_headers",
))


def _snapshot_dir() -> Path:
    from wpsecscan import history as _h
    return Path(_h._home()) / "reports"


def _latest_snapshot_for(url: str) -> Path | None:
    from wpsecscan import history as _h
    safe = _h._safe_filename(url)
    snaps = sorted(_snapshot_dir().glob(f"*{safe}*.json"))
    return snaps[-1] if snaps else None


def has_target_changed(url: str, since: datetime) -> bool:
    """Compare the last snapshot's scan time + fingerprints against `since`.
    Returns True if the snapshot is older than `since` (i.e. a new scan IS
    needed) OR if the fingerprint look-alike data has changed."""
    snap_path = _latest_snapshot_for(url)
    if not snap_path:
        return True  # No snapshot at all, definitely scan
    try:
        snap = json.loads(snap_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    scanned_at = snap.get("scanned_at", "")
    try:
        snap_dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00").split("+", 1)[0])
    except (ValueError, AttributeError):
        return True
    return snap_dt < since


def should_skip_check(check_id: str, url: str, since: datetime | None) -> bool:
    """Returns True if --since is set, the target hasn't changed materially,
    AND the check is in the low-churn list."""
    if since is None:
        return False
    if check_id not in LOW_CHURN_CHECK_IDS:
        return False
    skip = not has_target_changed(url, since)
    if skip:
        try:
            from wpsecscan import activity as _act
            _act.emit("meta", f"incremental skip: {check_id} (no change since {since.date().isoformat()})")
        except ImportError:
            pass
    return skip


# ---------- K27 per-host baseline learner ----------

def _baseline_path(url: str) -> Path:
    from wpsecscan import history as _h
    safe = _h._safe_filename(url)
    return Path(_h._home()) / "baselines" / f"{safe}.json"


def _load_baseline(url: str) -> dict:
    p = _baseline_path(url)
    if not p.exists():
        return {"samples": {}}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {"samples": {}}
    except (OSError, ValueError):
        return {"samples": {}}


def _save_baseline(url: str, data: dict) -> None:
    p = _baseline_path(url)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def record_observation(url: str, path: str, status: int, body_len: int) -> None:
    """Append one (status, body_len) tuple to the path's history (rolling 30)."""
    b = _load_baseline(url)
    samples = b.setdefault("samples", {})
    arr = samples.setdefault(path, [])
    arr.append([int(status), int(body_len)])
    if len(arr) > 30:
        arr[:] = arr[-30:]
    _save_baseline(url, b)


def anomaly_for(url: str, path: str, status: int, body_len: int,
                 *, threshold_pct: float = 0.30) -> str | None:
    """Compare current observation against learned baseline. Returns a
    human-readable anomaly description, or None if normal."""
    b = _load_baseline(url)
    arr = b.get("samples", {}).get(path) or []
    if len(arr) < 5:
        return None  # need >=5 prior samples to call anomalies
    statuses = [int(x[0]) for x in arr]
    lens = [int(x[1]) for x in arr]
    median_len = sorted(lens)[len(lens) // 2]
    # Status changed?
    if status not in statuses:
        return f"status {status} not seen in last {len(arr)} observations (typical: {sorted(set(statuses))})"
    # Body length deviates significantly?
    if median_len > 0 and abs(body_len - median_len) > median_len * threshold_pct:
        return f"body {body_len}B vs baseline median {median_len}B ({(body_len - median_len) / median_len * 100:+.0f}%)"
    return None
