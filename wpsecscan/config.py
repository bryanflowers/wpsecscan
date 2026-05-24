"""Round-61 — persistent user-preferences for the GUI.

Lives at `~/.wpsecscan/config.json`. Read-once-on-launch, write-on-save.
Schema is intentionally simple — flat dict, additive over releases.

Fields (all optional, every getter has a default):
  theme          str — "dark" | "light" | "matrix" | "hacker" | "corporate" |
                       "high-contrast" | "sv-ttk-dark" | "sv-ttk-light"
  follow_os_theme bool — if true, theme is recomputed on each launch
  mode           str — "beginner" | "standard" | "expert"
  last_url       str — pre-fill the URL field
  show_welcome   bool — show the first-run welcome dialog
  proxy_url      str — global proxy default (overridable per-site)
  proxy_auth     str — "user:pass" (sealed at rest if hardware_keys avail.)
  ai_opt_in      bool — gates Tools→AI menu visibility
  compliance_framework str — default framework (hitrust / cmmc / nist_csf / cis_v8 / iso_27001_2022)

Pure-function API:
    cfg = load()              # returns dict, never raises
    save(theme="light")       # partial update
    get("mode", "standard")   # single-key with default
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


_DEFAULTS: dict[str, Any] = {
    "theme":           "dark",
    "follow_os_theme": True,
    "mode":            "standard",   # beginner / standard / expert
    "last_url":        "",
    "show_welcome":    True,
    "proxy_url":       "",
    "proxy_auth":      "",
    "ai_opt_in":       False,
    "compliance_framework": "",
}

VALID_MODES = ("beginner", "standard", "expert")
VALID_THEMES = ("dark", "light", "matrix", "hacker", "corporate",
                 "high-contrast", "sv-ttk-dark", "sv-ttk-light")


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def config_path() -> Path:
    return _home() / "config.json"


def load() -> dict:
    p = config_path()
    if not p.exists():
        return dict(_DEFAULTS)
    try:
        raw = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return dict(_DEFAULTS)
    if not isinstance(raw, dict):
        return dict(_DEFAULTS)
    merged = dict(_DEFAULTS)
    merged.update({k: v for k, v in raw.items() if k in _DEFAULTS})
    # Validate enum-like fields; fall back to default on invalid
    if merged["mode"] not in VALID_MODES:
        merged["mode"] = _DEFAULTS["mode"]
    if merged["theme"] not in VALID_THEMES:
        merged["theme"] = _DEFAULTS["theme"]
    return merged


def save(**updates: Any) -> dict:
    """Partial update + persist. Returns the merged config."""
    current = load()
    for k, v in updates.items():
        if k in _DEFAULTS:
            current[k] = v
    if current["mode"] not in VALID_MODES:
        current["mode"] = _DEFAULTS["mode"]
    if current["theme"] not in VALID_THEMES:
        current["theme"] = _DEFAULTS["theme"]
    p = config_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(current, indent=2), encoding="utf-8")
    except OSError:
        pass
    return current


def get(key: str, default: Any = None) -> Any:
    cfg = load()
    if key in cfg:
        return cfg[key]
    return default if default is not None else _DEFAULTS.get(key)


def reset() -> dict:
    p = config_path()
    if p.exists() and not p.is_symlink():
        try:
            p.unlink()
        except OSError:
            pass
    return dict(_DEFAULTS)


# ---- Convenience helpers for the GUI ----

def is_expert() -> bool:
    return load().get("mode") == "expert"


def is_beginner() -> bool:
    return load().get("mode") == "beginner"


def effective_theme() -> str:
    """Resolve the theme to use right now.

    If `follow_os_theme` is True, returns "sv-ttk-dark" or "sv-ttk-light"
    based on the OS preference (uses ux_extras.current_os_theme()). Falls
    back to the user's saved theme on detection failure.
    """
    cfg = load()
    saved = cfg.get("theme", "dark")
    if not cfg.get("follow_os_theme"):
        return saved
    try:
        from . import ux_extras
        os_theme = ux_extras.current_os_theme()
    except ImportError:
        return saved
    except (AttributeError, OSError):
        # Platform-detection libs can raise on edge OSes — fall back.
        return saved
    if os_theme == "dark":
        return "sv-ttk-dark"
    if os_theme == "light":
        return "sv-ttk-light"
    return saved
