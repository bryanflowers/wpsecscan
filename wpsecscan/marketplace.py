"""F5 Plugin / signature / payload marketplace — static curated list.

The catalogue lives in data/marketplace.json (shipped with the package).
The marketplace browser GUI lists entries by category and copies the
source URL to the clipboard — the user is expected to manually inspect
and place the file under ~/.wpsecscan/{signatures,payloads,plugins}/.

We deliberately do NOT auto-download or auto-install. Security tools are
prime supply-chain targets — every drop-in should be reviewed by a human
before it touches the scanner.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _catalogue_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "marketplace.json"
    return Path(__file__).resolve().parent / "data" / "marketplace.json"


def load_catalogue() -> dict:
    """Return the {categories, entries} dict from the static catalogue."""
    p = _catalogue_path()
    if not p.exists():
        return {"categories": [], "entries": []}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {"categories": [], "entries": []}
    return {
        "categories": d.get("categories") or [],
        "entries": d.get("entries") or [],
    }


def entries_by_category(category: str | None = None) -> list[dict]:
    """Filter the catalogue by category. None returns everything."""
    cat = load_catalogue()
    if not category:
        return list(cat.get("entries", []))
    return [e for e in cat.get("entries", []) if e.get("category") == category]
