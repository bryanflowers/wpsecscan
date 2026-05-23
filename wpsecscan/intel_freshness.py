"""#39 — CVE intel freshness scoreboard.

Per-source "last updated" timestamps so the user knows their KEV / EPSS /
Wordfence / Patchstack data isn't 30 days stale. Pulled into the
end-of-scan stats panel + the GUI Tools menu.

Sources tracked (file path / cache-age):
  - CISA KEV         (~/.wpsecscan/cisa_kev.json)
  - EPSS             (~/.wpsecscan/epss_cache.json)
  - Wordfence DB     (~/.wpsecscan/cves.db or embedded fallback)
  - Patchstack DB    (only if --patchstack-token was used; same DB file)
  - VirusTotal cache (per-URL — we don't track at file level)
  - Sucuri cache     (~/.wpsecscan/sucuri_cache.json)
  - CVE explainer    (~/.wpsecscan/cve_explainer.json)
"""
from __future__ import annotations

import os
import time
from pathlib import Path


SOURCES = {
    "CISA KEV":       "cisa_kev.json",
    "EPSS":           "epss_cache.json",
    "Wordfence CVEs": "cves.db",
    "Sucuri":         "sucuri_cache.json",
    "CVE explainer":  "cve_explainer.json",
}


def _home() -> Path:
    from . import history as _h
    return Path(_h._home())


def report() -> list[dict]:
    """Return [{source, age_hours, status}] for every known intel source."""
    out = []
    now = time.time()
    home = _home()
    for label, fname in SOURCES.items():
        p = home / fname
        if not p.exists():
            out.append({"source": label, "age_hours": None, "status": "missing"})
            continue
        try:
            age_s = now - p.stat().st_mtime
        except OSError:
            out.append({"source": label, "age_hours": None, "status": "unreadable"})
            continue
        age_h = age_s / 3600
        if age_h < 24:
            status = "fresh"
        elif age_h < 168:  # 1 week
            status = "ok"
        elif age_h < 720:  # 30 days
            status = "stale"
        else:
            status = "very stale"
        out.append({"source": label, "age_hours": int(age_h), "status": status})
    return out


def render_text() -> str:
    """Human-friendly multi-line string for end-of-scan output."""
    lines = ["Intel freshness:"]
    for entry in report():
        age = entry["age_hours"]
        age_str = "missing" if age is None else (
            f"{age}h" if age < 48 else f"{age // 24}d")
        lines.append(f"  - {entry['source']:18} {entry['status']:11} ({age_str})")
    return "\n".join(lines)
