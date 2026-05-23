"""I12 References loader — maps check_id -> reference URLs."""
from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent / "data"


@lru_cache(maxsize=1)
def _load() -> dict:
    p = _data_dir() / "references.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def for_check(check_id: str) -> dict[str, str]:
    """Return {primary, deep_dive, video} dict for a check_id (any missing keys absent)."""
    d = _load()
    out = d.get(check_id) or {}
    return {k: v for k, v in out.items() if isinstance(v, str) and v}
