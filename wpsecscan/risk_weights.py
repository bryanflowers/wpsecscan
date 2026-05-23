"""I16 User-tunable severity weights.

`compute_risk_score` defaults to:
  critical: 25 × n, capped at 50
  high:     10 × n, capped at 30
  medium:    3 × n, capped at 12
  low:       1 × n, capped at  8
  info:      0

Some teams care less about info / low, others insist medium = high. This
module loads overrides from ~/.wpsecscan/risk_weights.json so teams can
edit the formula without forking the tool.

Schema (every field optional, falls back to default):
  {
    "critical": {"per_finding": 30, "cap": 60},
    "high":     {"per_finding": 15, "cap": 40},
    ...
  }
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


DEFAULT_WEIGHTS = {
    "critical": {"per_finding": 25, "cap": 50},
    "high":     {"per_finding": 10, "cap": 30},
    "medium":   {"per_finding": 3,  "cap": 12},
    "low":      {"per_finding": 1,  "cap": 8},
    "info":     {"per_finding": 0,  "cap": 0},
}


def _path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "risk_weights.json"


@lru_cache(maxsize=1)
def load_weights() -> dict[str, dict[str, int]]:
    """Merge user overrides over the defaults. Cached for the process."""
    p = _path()
    out = {k: dict(v) for k, v in DEFAULT_WEIGHTS.items()}
    if not p.exists():
        return out
    try:
        user = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return out
    for sev, override in user.items():
        if sev not in out or not isinstance(override, dict):
            continue
        if "per_finding" in override and isinstance(override["per_finding"], (int, float)):
            out[sev]["per_finding"] = int(override["per_finding"])
        if "cap" in override and isinstance(override["cap"], (int, float)):
            out[sev]["cap"] = int(override["cap"])
    return out


def save_weights(weights: dict[str, dict[str, int]]) -> None:
    """Persist a weights dict. Invalidates the loader cache."""
    p = _path()
    try:
        p.write_text(json.dumps(weights, indent=2), encoding="utf-8")
        load_weights.cache_clear()
    except OSError:
        pass


def reset_to_defaults() -> None:
    p = _path()
    try:
        if p.exists():
            p.unlink()
        load_weights.cache_clear()
    except OSError:
        pass
