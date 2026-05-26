"""Risk score — a single 0-100 number per ScanReport.

Weighted by severity, capped per-tier so one runaway check can't dominate.
Color tiers: 90+ green, 70-89 yellow, 40-69 orange, <40 red.
"""
from __future__ import annotations

import ast

from .models import ScanReport


# Item #60 — node types allowed in a user-supplied risk formula. Anything
# else (Call, Attribute, Import, etc.) is rejected to keep the expression
# safe-by-default. Operators: +, -, *, /, //, %, **, unary -, comparisons,
# and ternary `a if cond else b`.
_FORMULA_ALLOWED = (
    ast.Expression, ast.Constant, ast.Name, ast.Load, ast.Subscript,
    ast.Index, ast.Slice,  # Index is py<3.9 legacy; harmless to keep
    ast.BinOp, ast.UnaryOp,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd,
    ast.IfExp, ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.BoolOp, ast.And, ast.Or,
    ast.Tuple, ast.List,
)


def _evaluate_user_formula(expr: str, summary: dict[str, int],
                            risk_score_default: int) -> int | None:
    """Item #60 — evaluate a user-supplied risk formula safely.

    Bindings in the expression scope:
      critical, high, medium, low, info: int counts from `summary`
      base:    int, default formula's score (lets the user delta-adjust)

    Returns the clamped int 0..100, or None if the expression is unsafe / errors.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, _FORMULA_ALLOWED):
            return None
        if isinstance(node, ast.Name) and node.id not in {
            "critical", "high", "medium", "low", "info", "base",
        }:
            return None
    try:
        result = eval(  # noqa: S307 — AST-guarded; allowlist enforced above
            compile(tree, "<risk_formula>", "eval"),
            {"__builtins__": {}},
            {
                "critical": int(summary.get("critical", 0)),
                "high":     int(summary.get("high", 0)),
                "medium":   int(summary.get("medium", 0)),
                "low":      int(summary.get("low", 0)),
                "info":     int(summary.get("info", 0)),
                "base":     int(risk_score_default),
            },
        )
    except Exception:  # noqa: BLE001
        return None
    try:
        return max(0, min(100, int(result)))
    except (TypeError, ValueError):
        return None

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
    score = max(0, score)

    # Item #60 — `risk_formula` in policy.yml replaces the result entirely
    # via a safe AST-guarded Python expression. Used by teams who want a
    # bespoke formula (e.g. `100 - (5*critical + 3*high + 1*medium)`).
    try:
        from . import policy as _policy
        pol = _policy.load()
        expr = (pol or {}).get("risk_formula")
        if expr:
            user = _evaluate_user_formula(expr, report.summary, score)
            if user is not None:
                return user
    except Exception:  # noqa: BLE001 — never let policy break the scan
        pass
    return score


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
