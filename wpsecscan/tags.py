"""Per-check OWASP Top 10 + MITRE ATT&CK tagging.

Loads data/check_tags.json once, exposes get_tags(check_id). Reporters and
the GUI render small badges next to each check section ("A03:2021 · T1190").
Mapping is best-effort and conservative.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent / "data"


_CACHE: dict | None = None


def _load() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    f = _data_dir() / "check_tags.json"
    if not f.exists():
        _CACHE = {}
        return _CACHE
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        _CACHE = {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}
    except (OSError, json.JSONDecodeError):
        _CACHE = {}
    return _CACHE


def get_tags(check_id: str) -> dict | None:
    """Return {'owasp', 'owasp_label', 'attack', 'attack_label'} or None."""
    return _load().get(check_id)


_COMPLIANCE_CACHE: dict | None = None


def _load_compliance() -> dict:
    global _COMPLIANCE_CACHE
    if _COMPLIANCE_CACHE is not None:
        return _COMPLIANCE_CACHE
    f = _data_dir() / "compliance_map.json"
    if not f.exists():
        _COMPLIANCE_CACHE = {}
        return _COMPLIANCE_CACHE
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        _COMPLIANCE_CACHE = {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}
    except (OSError, json.JSONDecodeError):
        _COMPLIANCE_CACHE = {}
    return _COMPLIANCE_CACHE


def get_compliance(check_id: str) -> dict | None:
    """Return {'pci_dss', 'nist_800_53', 'iso_27001'} or None."""
    return _load_compliance().get(check_id)


def reset_cache() -> None:
    """Force the next get_tags() call to re-read the JSONs. For tests."""
    global _CACHE, _COMPLIANCE_CACHE
    _CACHE = None
    _COMPLIANCE_CACHE = None


def short_chip(check_id: str) -> str:
    """Inline rendering: 'A03:2021 · T1190' or '' if unknown."""
    t = get_tags(check_id)
    if not t:
        return ""
    bits = []
    if t.get("owasp"):
        bits.append(t["owasp"])
    if t.get("attack"):
        bits.append(t["attack"])
    return " · ".join(bits)
