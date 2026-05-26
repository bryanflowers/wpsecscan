"""FEAT-036 — continuous file-change monitor against the companion plugin.

Polls /wpsecscan/v1/file-monitor every N seconds, compares the SHA-256
manifest to the previous one, and fires a desktop notification + writes
to a watch log when any file changes outside an explicit "expected
update window" (currently anything — future work: integrate with
wp.org plugin/theme release feeds).

Usage from CLI: `wpsecscan --continuous URL --companion-token TOKEN`
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx

DEFAULT_INTERVAL_S = 300  # 5 minutes


def _state_path(home: Path, host: str) -> Path:
    return home / "watchers" / f"{host}-manifest.json"


async def _fetch_manifest(url: str, token: str, *, timeout: float = 30.0) -> dict | None:
    """One request against the companion's /file-monitor endpoint."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=True) as c:
            r = await c.get(url, headers={"X-WPSecScan-Token": token})
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def _diff_manifests(prev: dict, new: dict) -> dict:
    """Return added/removed/modified lists comparing manifest dicts."""
    p = (prev.get("manifest") or {}) if isinstance(prev, dict) else {}
    n = (new.get("manifest") or {}) if isinstance(new, dict) else {}
    added = [path for path in n if path not in p]
    removed = [path for path in p if path not in n]
    modified = [path for path in n if path in p and n[path] != p[path]]
    return {"added": added, "removed": removed, "modified": modified}


async def run(
    target: str,
    *,
    companion_token: str,
    interval_s: float = DEFAULT_INTERVAL_S,
    home: Path | None = None,
    on_change: Callable[[dict], None] | None = None,
    once: bool = False,
) -> int:
    """Run the monitor loop. Returns exit code (0 = clean shutdown)."""
    import os as _os
    from urllib.parse import urlparse
    if home is None:
        home = Path(_os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    host = (urlparse(target).hostname or "site").lower()
    state_file = _state_path(home, host)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    endpoint = target.rstrip("/") + "/wp-json/wpsecscan/v1/file-monitor"
    prev: dict | None = None
    if state_file.exists():
        try:
            prev = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = None
    while True:
        new = await _fetch_manifest(endpoint, companion_token)
        if new is None:
            print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] "
                  "fetch failed; will retry next interval")
        else:
            if prev:
                delta = _diff_manifests(prev, new)
                total = sum(len(v) for v in delta.values())
                if total > 0:
                    summary = (f"+{len(delta['added'])} ~{len(delta['modified'])} "
                               f"-{len(delta['removed'])} (total {total})")
                    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] "
                          f"FILE CHANGES on {host}: {summary}")
                    for p in delta["added"][:5]:
                        print(f"  + {p}")
                    for p in delta["modified"][:5]:
                        print(f"  ~ {p}")
                    for p in delta["removed"][:5]:
                        print(f"  - {p}")
                    if on_change:
                        on_change({"host": host, "delta": delta, "manifest": new})
                else:
                    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] "
                          f"{host}: no change ({new.get('count', 0)} files)")
            else:
                print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] "
                      f"initial manifest for {host}: {new.get('count', 0)} files")
            try:
                state_file.write_text(json.dumps(new), encoding="utf-8")
            except OSError:
                pass
            prev = new
        if once:
            return 0
        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            return 0
