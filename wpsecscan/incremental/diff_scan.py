"""Diff-scan: re-run only checks whose targets have changed.

Round-64 #162 — track per-(check, url) ETag + Last-Modified. On the
next scan, HEAD each target; if neither changed, mark the check as
"unchanged since last scan" and skip its expensive logic, reusing
the previous findings.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _state_path(target: str) -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    safe = "".join(c if c.isalnum() else "_" for c in target)
    return home / "incremental" / safe / "etag_cache.json"


def load_state(target: str) -> dict:
    p = _state_path(target)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(target: str, state: dict) -> None:
    p = _state_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(state, indent=2), encoding="utf-8")


def record(target: str, check_id: str, url_path: str, etag: str | None, last_modified: str | None) -> None:
    """Record post-fetch headers for a check's target."""
    s = load_state(target)
    s.setdefault(check_id, {})[url_path] = {"etag": etag, "last_modified": last_modified}
    save_state(target, s)


def unchanged_since(target: str, check_id: str, url_path: str, current_headers: dict) -> bool:
    """True if both ETag and Last-Modified match the last recorded values."""
    s = load_state(target).get(check_id, {}).get(url_path)
    if not s:
        return False
    cur_etag = current_headers.get("etag") or current_headers.get("ETag")
    cur_lm = current_headers.get("last-modified") or current_headers.get("Last-Modified")
    if not (cur_etag or cur_lm):
        return False
    if s.get("etag") and cur_etag and s["etag"] == cur_etag:
        return True
    if s.get("last_modified") and cur_lm and s["last_modified"] == cur_lm:
        return True
    return False


async def head_targets(client, paths: list[str]) -> dict[str, dict]:
    """HEAD each path, return {path: {etag, last_modified, status}}."""
    out = {}
    for p in paths:
        try:
            r = await client.head(p)
            if r is None:
                out[p] = {}
                continue
            out[p] = {
                "etag": r.headers.get("etag") or r.headers.get("ETag", ""),
                "last_modified": r.headers.get("last-modified") or r.headers.get("Last-Modified", ""),
                "status": r.status_code,
            }
        except Exception:  # noqa: BLE001
            out[p] = {}
    return out
