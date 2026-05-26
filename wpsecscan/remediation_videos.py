"""Item #47 — load + lookup curated remediation videos.

The static map lives at data/remediation_videos.json. Each entry has a
check_id regex (always required) and an optional title regex. The
HTML / Markdown reporters call ``video_for(check_id, title)`` and embed
a link beneath the remediation block when a match is found.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _load() -> list[dict]:
    p = Path(__file__).parent / "data" / "remediation_videos.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return list(data.get("videos") or [])
    except (OSError, ValueError):
        return []


@lru_cache(maxsize=512)
def video_for(check_id: str, title: str = "") -> dict | None:
    """Return the first matching video entry or None."""
    if not check_id:
        return None
    for entry in _load():
        cid_re = entry.get("check_id_pattern")
        title_re = entry.get("title_pattern")
        if not cid_re:
            continue
        try:
            if not re.search(cid_re, check_id, re.IGNORECASE):
                continue
        except re.error:
            continue
        if title_re and title:
            try:
                if not re.search(title_re, title, re.IGNORECASE):
                    continue
            except re.error:
                continue
        return dict(entry)
    return None
