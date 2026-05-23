"""O45 Per-finding 'did the fix work?' feedback.

A small JSON store at ~/.wpsecscan/fix_feedback.json keeping per-finding
verdicts after the user confirms (or denies) that the remediation worked.
Schema mirrors annotations: keyed by url+check_id+finding_title.

Used by the recommendation engine later (#future): de-prioritize remediation
text that consistently gets "didn't work" feedback, and flag remediation
text that's broadly confirmed as effective.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def _path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "fix_feedback.json"


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


def _key(url: str, check_id: str, finding_title: str) -> str:
    return f"{url}::{check_id}::{finding_title}"


def record(url: str, check_id: str, finding_title: str, worked: bool, note: str = "") -> None:
    d = _load()
    d[_key(url, check_id, finding_title)] = {
        "worked": bool(worked),
        "note": (note or "").strip()[:500],
        "ts": time.time(),
    }
    _save(d)


def get(url: str, check_id: str, finding_title: str) -> dict | None:
    return _load().get(_key(url, check_id, finding_title))


def summary_for_check(check_id: str) -> dict:
    """Return {"yes": N, "no": M, "total": N+M} for a check across all URLs."""
    d = _load()
    yes = no = 0
    for k, v in d.items():
        # key is url::cid::title — pick cid as the middle segment
        parts = k.split("::", 2)
        if len(parts) >= 2 and parts[1] == check_id:
            if v.get("worked"):
                yes += 1
            else:
                no += 1
    return {"yes": yes, "no": no, "total": yes + no}
