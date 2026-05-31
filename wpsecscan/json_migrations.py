"""v2.8.1 T6 — versioned-JSON state migration.

Several local-state JSON files have evolved their schema over releases
without a `version` field. Reading a v0 file with v2 code can silently
drop fields or crash. This module provides a uniform sniff-and-upgrade
helper that:

  * Reads a JSON file
  * If it has no `_schema_version`, infers one from shape
  * Runs registered upgraders to bring it to the current version
  * Returns the upgraded dict (and rewrites the file if `inplace=True`)

Files covered (v2.8.2 M1 — `audit-log.jsonl` removed; it's JSONL not
JSON and would crash json.loads on more than one line):
  - ~/.wpsecscan/replay-prompt-log.json
  - ~/.wpsecscan/web-push-subs.json
  - ~/.wpsecscan/marketplace/installed.json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

# Registered upgraders: {file_kind: [(from_version, to_version, fn), ...]}
_UPGRADERS: dict[str, list[tuple[int, int, Callable[[Any], Any]]]] = {}


def register(kind: str, *, from_v: int, to_v: int):
    """Decorator to register a single-step upgrader."""
    def _wrap(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
        _UPGRADERS.setdefault(kind, []).append((from_v, to_v, fn))
        return fn
    return _wrap


def load_versioned(path: str | Path, *, kind: str,
                    current_version: int,
                    inplace: bool = True,
                    backup: bool = False) -> Any:
    """Read `path`, infer/upgrade its version to `current_version`, return data.

    When `inplace=True`, the upgraded blob is written back to `path`. When
    `backup=True` (v2.8.2 L10), the original file is copied to `<path>.bak`
    BEFORE the in-place rewrite so a buggy upgrader can be recovered from.
    The default `backup=False` matches the v2.8.1 behaviour — opt in only
    for state files where data loss would be unrecoverable.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ver = 0
    if isinstance(data, dict):
        ver = data.get("_schema_version") or 0
    while ver < current_version:
        next_step = next(((f, t, fn) for (f, t, fn) in _UPGRADERS.get(kind, [])
                          if f == ver), None)
        if not next_step:
            break  # no path forward
        _, ver, fn = next_step
        data = fn(data)
        if isinstance(data, dict):
            data["_schema_version"] = ver
    if inplace and isinstance(data, dict):
        if backup:
            try:
                bak = p.with_suffix(p.suffix + ".bak")
                bak.write_bytes(p.read_bytes())
            except OSError:
                pass
        try:
            from .reporters import _atomic_write_text
            _atomic_write_text(p, json.dumps(data, indent=2))
        except (ImportError, OSError):
            pass
    return data


# Default upgraders — start at v0 (no version field) → v1 (add version + ts).
@register("replay_prompt_log", from_v=0, to_v=1)
def _replay_prompt_v0_to_v1(data: Any) -> Any:
    if not isinstance(data, list):
        return {"_schema_version": 1, "entries": []}
    return {"_schema_version": 1, "entries": data}


@register("web_push_subs", from_v=0, to_v=1)
def _web_push_v0_to_v1(data: Any) -> Any:
    if not isinstance(data, list):
        return {"_schema_version": 1, "subscriptions": []}
    return {"_schema_version": 1, "subscriptions": data}


@register("marketplace_installed", from_v=0, to_v=1)
def _marketplace_v0_to_v1(data: Any) -> Any:
    if not isinstance(data, dict):
        return {"_schema_version": 1, "installed": {}}
    if "installed" in data:
        return data
    return {"_schema_version": 1, "installed": data}
