"""G90 (v2.6.0) — false-positive predictor for new findings.

Trains an extremely small probabilistic classifier on the operator's
historical snooze decisions (stored at ~/.wpsecscan/snoozes.json by
the existing `snooze` subcommand). For every new finding, returns a
probability that the operator is likely to snooze this one too.

The classifier is intentionally simple — no scikit-learn / numpy dep:

  • For each (check_id, title-word) bigram observed in a snoozed
    finding's title, count +1 in P(snooze|bigram).
  • For each bigram observed in NEW findings the operator did NOT
    snooze, count +1 in P(no_snooze|bigram).
  • Compute Laplace-smoothed Bayes posterior at predict time.

Reporters can decorate findings with `extra.fp_score` (0..1) so the
operator sees "likely FP" badges. Predictor never alters severity —
the human decision remains the source of truth.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from ._util import home_dir, load_home_json


_WORD_RE = re.compile(r"[a-z0-9]{3,}")


def _tokens(title: str) -> list[str]:
    return _WORD_RE.findall((title or "").lower())


def _features(check_id: str, title: str) -> list[str]:
    toks = _tokens(title)
    out = [f"cid:{check_id}"]
    for t in toks:
        out.append(f"w:{t}")
        out.append(f"cw:{check_id}|{t}")
    return out


def _load_snoozes() -> list[dict]:
    """Read ~/.wpsecscan/snoozes.json (list of {check_id, title, ...})."""
    raw = load_home_json("snoozes.json", [])
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    return []


def _load_unsnoozed_history() -> list[dict]:
    """Walk a few recent ~/.wpsecscan/reports/ snapshots to learn what
    the operator left UN-snoozed (positive evidence)."""
    reports = home_dir() / "reports"
    if not reports.exists():
        return []
    out: list[dict] = []
    for p in sorted(reports.glob("*.json"))[-10:]:  # last 10 snapshots
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for r in d.get("results", []):
            cid = r.get("check_id", "")
            for f in r.get("findings", []):
                out.append({"check_id": cid, "title": f.get("title", "")})
    return out


def _train(snoozes: list[dict], unsnoozed: list[dict]) -> dict[str, float]:
    """Return a dict feature → log-likelihood-ratio (snooze vs not)."""
    snz: dict[str, int] = {}
    pos: dict[str, int] = {}
    for s in snoozes:
        for feat in _features(s.get("check_id", ""), s.get("title", "")):
            snz[feat] = snz.get(feat, 0) + 1
    for u in unsnoozed:
        for feat in _features(u.get("check_id", ""), u.get("title", "")):
            pos[feat] = pos.get(feat, 0) + 1
    # Laplace +1 smoothing
    n_s = sum(snz.values()) + 1
    n_p = sum(pos.values()) + 1
    out: dict[str, float] = {}
    for feat in set(snz) | set(pos):
        p_s = (snz.get(feat, 0) + 1) / n_s
        p_p = (pos.get(feat, 0) + 1) / n_p
        out[feat] = math.log(p_s / p_p)
    return out


def predict_fp_probability(check_id: str, title: str) -> float:
    """Return P(this finding will be snoozed) in [0, 1].

    Returns 0.0 when there's no training data (no historical snoozes),
    so reporters can use the score to decorate without ever penalising
    a clean-slate install.
    """
    snoozes = _load_snoozes()
    if not snoozes:
        return 0.0
    weights = _train(snoozes, _load_unsnoozed_history())
    log_odds = 0.0
    for feat in _features(check_id, title):
        log_odds += weights.get(feat, 0.0)
    # Logistic squash to [0,1]
    try:
        return 1.0 / (1.0 + math.exp(-log_odds))
    except OverflowError:
        return 0.0 if log_odds < 0 else 1.0


def annotate_report(report) -> int:
    """Mutate `report.results` in-place: decorate every finding with
    `extra.fp_score = float`. Returns the count of annotated findings.
    """
    snoozes = _load_snoozes()
    if not snoozes:
        return 0
    weights = _train(snoozes, _load_unsnoozed_history())
    n = 0
    for r in report.results:
        for f in r.findings:
            log_odds = sum(weights.get(feat, 0.0)
                            for feat in _features(r.check_id, f.title))
            try:
                p = 1.0 / (1.0 + math.exp(-log_odds))
            except OverflowError:
                p = 0.0 if log_odds < 0 else 1.0
            f.extra["fp_score"] = round(p, 3)
            n += 1
    return n
