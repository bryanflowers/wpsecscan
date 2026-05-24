"""Trend over time — sparkline of finding counts per scan.

Round-64 #96 — reads `~/.wpsecscan/history/<target>/scans.jsonl` and
emits a simple SVG sparkline showing critical+high counts over time.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _history_path(target: str) -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    safe_target = "".join(c if c.isalnum() else "_" for c in target)
    return home / "history" / safe_target / "scans.jsonl"


def load_history(target: str, max_entries: int = 30) -> list[dict]:
    """Each line in the file is a scan summary dict. Return last N."""
    p = _history_path(target)
    if not p.exists():
        return []
    entries = []
    try:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return entries[-max_entries:]


def render_sparkline_svg(target: str, history: list[dict], *, width: int = 240, height: int = 60) -> str:
    if not history:
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><text x="10" y="30" font-family="sans-serif" font-size="12">No history yet</text></svg>'
    # Sum critical + high per entry as the "danger score"
    values = []
    for entry in history:
        s = entry.get("summary", {}) if isinstance(entry, dict) else {}
        values.append(int(s.get("critical", 0)) * 3 + int(s.get("high", 0)))
    vmax = max(values) or 1
    n = len(values)
    if n == 1:
        values = values * 2
        n = 2
    step = width / (n - 1)
    pts = []
    for i, v in enumerate(values):
        x = i * step
        y = height - (height - 8) * (v / vmax) - 4
        pts.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(pts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        f'<polyline fill="none" stroke="#e64a19" stroke-width="2" points="{polyline}"/>'
        f'<text x="2" y="12" font-family="sans-serif" font-size="9" fill="#555">{target}</text>'
        f'<text x="{width - 30}" y="{height - 2}" font-family="sans-serif" font-size="9" fill="#555">{n} scans</text>'
        f'</svg>'
    )


def append_to_history(target: str, summary: dict, scanned_at: str | None = None) -> None:
    """Symlink-safe append to ~/.wpsecscan/history/<target>/scans.jsonl."""
    from datetime import datetime, timezone
    p = _history_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    entry = {
        "scanned_at": scanned_at or datetime.now(tz=timezone.utc).isoformat(),
        "summary": summary,
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
