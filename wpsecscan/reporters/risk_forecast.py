"""C54 (v2.7.0) — risk-score forecast.

Linear-regression projection of the score 30/60/90 days into the
future, using the saved snapshot history. Returns a small dict
suitable for embedding in the board 1-pager / agency dashboard.

Slope is computed via ordinary least squares on (timestamp,
risk_score) pairs. Confidence is gated by N: <3 snapshots = no
forecast (info-only); 3-9 = "low-confidence" tag; 10+ = "ok".
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path


def _safe_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00").split("+", 1)[0])
    except (ValueError, AttributeError):
        return None


def _read_history(target: str) -> list[tuple[float, int]]:
    """Return [(unix_ts, risk_score), ...] from saved snapshots."""
    try:
        from .. import history as _h
        snaps = _h.snapshot_history(target)
    except (ImportError, AttributeError):
        snaps = []
    out: list[tuple[float, int]] = []
    for p in snaps:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            dt = _safe_dt(d.get("scanned_at", ""))
            score = d.get("risk_score")
            if dt and isinstance(score, int):
                out.append((dt.timestamp(), score))
        except (OSError, ValueError):
            continue
    return out


def _ols_slope(points: list[tuple[float, int]]) -> tuple[float, float]:
    """Return (slope_per_day, intercept) — units per day on the time axis."""
    if len(points) < 2:
        return 0.0, points[0][1] if points else 100.0
    n = len(points)
    mean_x = sum(p[0] for p in points) / n
    mean_y = sum(p[1] for p in points) / n
    num = sum((p[0] - mean_x) * (p[1] - mean_y) for p in points)
    den = sum((p[0] - mean_x) ** 2 for p in points) or 1.0
    slope_per_sec = num / den
    slope_per_day = slope_per_sec * 86400
    intercept = mean_y - slope_per_sec * mean_x
    return slope_per_day, intercept


def forecast(target: str) -> dict:
    """Return forecast dict with projected scores at +30 / +60 / +90 days."""
    points = _read_history(target)
    if not points:
        return {"confidence": "none", "available": False, "snapshots": 0}
    points.sort(key=lambda p: p[0])
    slope, intercept = _ols_slope(points)
    latest_ts = points[-1][0]
    latest_score = points[-1][1]
    out = {"available": True, "snapshots": len(points),
            "latest_score": latest_score,
            "slope_per_day": round(slope, 4),
            "trend": "improving" if slope > 0 else ("worsening" if slope < 0 else "flat")}
    if len(points) < 3:
        out["confidence"] = "none"
    elif len(points) < 10:
        out["confidence"] = "low"
    else:
        out["confidence"] = "ok"
    for days in (30, 60, 90):
        projected = max(0, min(100, int(round(latest_score + slope * days))))
        out[f"projected_+{days}d"] = projected
        out[f"projected_+{days}d_date"] = (
            datetime.fromtimestamp(latest_ts) + timedelta(days=days)
        ).date().isoformat()
    return out


def render_text(forecast_dict: dict) -> str:
    """One-line human-readable form for stdout / report appendix."""
    if not forecast_dict.get("available"):
        return "Forecast: no history yet (need >= 2 saved snapshots)."
    d = forecast_dict
    conf = d.get("confidence", "?")
    return (
        f"Risk-score forecast (confidence: {conf}, {d['snapshots']} snapshots): "
        f"now={d['latest_score']} → +30d={d['projected_+30d']} "
        f"+60d={d['projected_+60d']} +90d={d['projected_+90d']} "
        f"(trend: {d['trend']}, slope={d['slope_per_day']:+.2f}/day)"
    )
