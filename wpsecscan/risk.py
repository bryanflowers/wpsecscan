"""Risk score — a single 0-100 number per ScanReport.

Weighted by severity, capped per-tier so one runaway check can't dominate.
Color tiers: 90+ green, 70-89 yellow, 40-69 orange, <40 red.
"""
from __future__ import annotations

from .models import ScanReport

# Per-finding weight, then cap on total deduction per tier
SEVERITY_WEIGHTS = {
    "critical": (25, 50),
    "high":     (10, 30),
    "medium":   (3, 12),
    "low":      (1, 8),
    "info":     (0, 0),
}


def compute_risk_score(report: ScanReport) -> int:
    """Return integer 0-100. 100 = no actionable findings; 0 = critical issues.

    Honours user-tuned overrides from ~/.wpsecscan/risk_weights.json (I16);
    when no overrides are present, behaves identically to the legacy formula.
    """
    try:
        from .risk_weights import load_weights
        weights = load_weights()
    except Exception:  # noqa: BLE001
        weights = None

    score = 100
    # `weights is not None` distinguishes "user has no override file" (returns
    # the default-merged dict) from "load_weights raised" (returns None and we
    # fall back to the legacy SEVERITY_WEIGHTS tuple). An empty dict still
    # uses the overrides path, which is correct: load_weights never returns
    # empty — it always merges defaults first.
    if weights is not None:
        for sev, spec in weights.items():
            n = report.summary.get(sev, 0)
            weight = int(spec.get("per_finding", 0))
            cap = int(spec.get("cap", 0))
            if not weight:
                continue
            score -= min(n * weight, cap)
    else:
        for sev, (weight, cap) in SEVERITY_WEIGHTS.items():
            n = report.summary.get(sev, 0)
            if not weight:
                continue
            score -= min(n * weight, cap)
    return max(0, score)


def risk_tier(score: int) -> str:
    """Return one of: 'green', 'yellow', 'orange', 'red'."""
    if score >= 90:
        return "green"
    if score >= 70:
        return "yellow"
    if score >= 40:
        return "orange"
    return "red"


def risk_label(score: int) -> str:
    """Short prose label for the score."""
    if score >= 90:
        return "Looks healthy"
    if score >= 70:
        return "A few issues — worth fixing"
    if score >= 40:
        return "Multiple issues — prioritize"
    return "Significant exposure — fix immediately"


def risk_grade(score: int) -> str:
    """A–F letter grade for non-technical stakeholders. Maps to tier colors.
    A: 95+   B: 85-94   C: 70-84   D: 50-69   F: <50"""
    if score >= 95:
        return "A"
    if score >= 85:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"
