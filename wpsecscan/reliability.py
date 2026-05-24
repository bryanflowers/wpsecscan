"""Round-59 #92-94 — Self-aware reliability.

Pure observability + alerting. No network — everything reads/writes
under `~/.wpsecscan/`. Each public function is safe to call from any
thread.

#92 Performance regression detection — keep a rolling per-check
    median+stddev; flag when a new run exceeds median + 2*stddev.
#93 Per-target perf alerts — fires `alert(message)` (uses notify.py)
    when a target's total scan time jumps 50%+ over the last 10 runs.
#94 Cache-hit-rate trend graph — `cache_trend()` returns a list of
    (timestamp, hit_rate) tuples from the last 30 days for the GUI/CLI
    to plot.
"""
from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


# ---- #92 Performance regression detection ----

_PERF_PATH_NAME = "perf_history.json"
_PERF_MAX = 200  # cap history per check_id


def _perf_path() -> Path:
    return _home() / _PERF_PATH_NAME


def _load_perf() -> dict:
    p = _perf_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_perf(data: dict) -> None:
    p = _perf_path()
    try:
        if p.is_symlink():
            p.unlink()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def record_check_duration(check_id: str, duration_ms: int) -> dict:
    """Append a sample. Returns regression-verdict dict
    `{regressed: bool, median: int, stddev: int, threshold: int, latest: int}`.

    Heuristic: regressed iff len(history) >= 10 AND
    duration_ms > median + 2*stddev AND duration_ms > 1000ms (filter noise).
    """
    if not check_id or duration_ms < 0:
        return {"regressed": False}
    data = _load_perf()
    series = data.setdefault(check_id, [])
    series.append(int(duration_ms))
    if len(series) > _PERF_MAX:
        series[:] = series[-_PERF_MAX:]
    data[check_id] = series
    _save_perf(data)

    verdict = {"regressed": False, "latest": int(duration_ms)}
    if len(series) >= 10:
        prior = series[:-1]
        med = int(statistics.median(prior))
        std = int(statistics.pstdev(prior)) if len(prior) > 1 else 0
        thr = med + 2 * std
        verdict.update({"median": med, "stddev": std, "threshold": thr,
                          "regressed": duration_ms > thr and duration_ms > 1000})
    return verdict


# ---- #93 Per-target perf alerts ----

_TARGET_PATH_NAME = "target_perf.json"


def _target_path() -> Path:
    return _home() / _TARGET_PATH_NAME


def record_target_total(target: str, total_ms: int) -> dict:
    """Append + alert if 50%+ regression over last 10."""
    if not target or total_ms < 0:
        return {"alerted": False}
    p = _target_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        data = {}
    series = data.setdefault(target, [])
    series.append({"ts": int(time.time()), "ms": int(total_ms)})
    if len(series) > 200:
        series[:] = series[-200:]
    data[target] = series

    verdict = {"alerted": False, "latest_ms": int(total_ms)}
    if len(series) >= 11:
        recent = [s["ms"] for s in series[-11:-1]]
        if recent:
            med = statistics.median(recent)
            ratio = (total_ms / med) if med > 0 else 1.0
            if ratio > 1.5:
                verdict.update({"alerted": True, "ratio": round(ratio, 2),
                                 "median": int(med)})
                try:
                    from . import notify
                    notify.notify(
                        f"WPSecScan: {target} scan time +{int((ratio - 1) * 100)}% over median",
                        f"latest={total_ms}ms, median={int(med)}ms (last 10)",
                    )
                except Exception:  # noqa: BLE001
                    pass
    try:
        if p.is_symlink():
            p.unlink()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
    return verdict


# ---- #94 Cache-hit-rate trend graph ----

_CACHE_TREND_NAME = "cache_trend.json"


def _cache_trend_path() -> Path:
    return _home() / _CACHE_TREND_NAME


def record_cache_stats(target: str, hits: int, misses: int) -> None:
    if not target or hits < 0 or misses < 0:
        return
    p = _cache_trend_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        data = {}
    series = data.setdefault(target, [])
    total = hits + misses
    rate = (hits / total) if total > 0 else 0.0
    series.append({"ts": int(time.time()), "hits": hits, "misses": misses,
                    "rate": round(rate, 4)})
    if len(series) > 200:
        series[:] = series[-200:]
    data[target] = series
    try:
        if p.is_symlink():
            p.unlink()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def cache_trend(target: str, days: int = 30) -> list[dict]:
    """Return entries from the last `days` days for plotting."""
    p = _cache_trend_path()
    if not p.exists() or not target:
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return []
    series = data.get(target) or []
    cutoff = int(time.time()) - max(1, int(days)) * 86400
    return [s for s in series if int(s.get("ts", 0)) >= cutoff]
