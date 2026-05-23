"""#45 + #46 — risk-aging engine + risk-acceptance with expiry.

#45: a finding unresolved for N days auto-escalates severity by one tier
    (low → medium → high → critical). Tracked in ~/.wpsecscan/risk_aging.json
    using the same fingerprint as annotations.

#46: annotations get an optional `valid_until` ISO date; when expired,
    re-fires as a fresh finding even if previously marked accepted-risk.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path


SEVERITY_LADDER = ("info", "low", "medium", "high", "critical")
AGE_ESCALATION_DAYS = 30  # bump severity by one tier every 30d


def _path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "risk_aging.json"


def _load() -> dict:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    try:
        _path().write_text(json.dumps(d, indent=2), encoding="utf-8")
    except OSError:
        pass


def mark_first_seen(fingerprint: str, original_severity: str) -> None:
    """Record that we first saw this finding now. No-op if already tracked."""
    d = _load()
    if fingerprint in d:
        return
    d[fingerprint] = {"first_seen_ts": time.time(),
                      "original_severity": original_severity,
                      "current_severity": original_severity}
    _save(d)


def age_escalate(fingerprint: str) -> str | None:
    """Bump severity by one tier if older than AGE_ESCALATION_DAYS. Returns
    new severity if changed, else None."""
    d = _load()
    entry = d.get(fingerprint)
    if not entry:
        return None
    age_days = (time.time() - entry["first_seen_ts"]) / 86400
    bumps = int(age_days // AGE_ESCALATION_DAYS)
    if bumps == 0:
        return None
    try:
        idx = SEVERITY_LADDER.index(entry["original_severity"])
        new_idx = min(len(SEVERITY_LADDER) - 1, idx + bumps)
        new_sev = SEVERITY_LADDER[new_idx]
    except ValueError:
        return None
    if new_sev != entry.get("current_severity"):
        entry["current_severity"] = new_sev
        d[fingerprint] = entry
        _save(d)
        return new_sev
    return None


# #46 — annotation expiry
def is_annotation_expired(annotation: dict) -> bool:
    """Return True if `annotation` has a `valid_until` field that's in the past."""
    valid_until = annotation.get("valid_until")
    if not valid_until:
        return False
    try:
        d = datetime.fromisoformat(valid_until.replace("Z", "+00:00").split("+", 1)[0])
        return d < datetime.now()
    except (ValueError, AttributeError):
        return False
