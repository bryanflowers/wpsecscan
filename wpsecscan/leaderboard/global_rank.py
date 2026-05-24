"""Opt-in 'your site vs WP average' ranking.

Round-64 #172 — submits the current site's anonymised summary to the
community-shared scan DB (#123) and gets back a percentile rank in
return.

Strictly opt-in via WPSECSCAN_PUBLIC_SHARE=1.
"""
from __future__ import annotations

import hashlib
import os
import uuid

import httpx


LEADERBOARD_URL = os.environ.get(
    "WPSECSCAN_LEADERBOARD_URL",
    "https://leaderboard.wpsecscan.com/api/v1/submit"
)


def _submitter_uuid() -> str:
    """Quarterly-rotating UUID stored locally."""
    from datetime import datetime, timezone
    from pathlib import Path
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    home.mkdir(parents=True, exist_ok=True)
    p = home / ".submitter_uuid"
    # Rotate quarterly: yyyyq + uuid
    now = datetime.now(tz=timezone.utc)
    quarter = (now.month - 1) // 3 + 1
    quarter_key = f"{now.year}-Q{quarter}"
    if p.exists():
        try:
            stored = p.read_text(encoding="utf-8").strip().split(":", 1)
            if len(stored) == 2 and stored[0] == quarter_key:
                return stored[1]
        except OSError:
            pass
    # Generate new
    new_uuid = str(uuid.uuid4())
    if p.is_symlink():
        p.unlink()
    p.write_text(f"{quarter_key}:{new_uuid}", encoding="utf-8")
    return new_uuid


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def submit(target: str, summary: dict, wpsecscan_version: str = "2.2.0") -> dict | None:
    """Submit + return {'percentile': N, 'rank': N, 'population': N} or None."""
    if not os.environ.get("WPSECSCAN_PUBLIC_SHARE"):
        return None
    submitter = _submitter_uuid()
    payload = {
        "target_hash":    _hash(target + submitter),
        "submitter_hash": _hash(submitter),
        "wpsecscan_version": wpsecscan_version,
        "summary":        summary,
    }
    try:
        r = httpx.post(LEADERBOARD_URL, json=payload, timeout=15.0)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None
