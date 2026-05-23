"""Scan duration estimator.

Pure data lookups based on typical measured durations against wordpress.org.
The estimator multiplies a per-check baseline by the number of enabled toggle
groups. Deep throttle dominates: 120 attempts × 10s = 20 min.
"""
from __future__ import annotations

# Baseline seconds per check group (rough, measured against wordpress.org).
PASSIVE_TOTAL_S = 60      # all 50ish passive checks combined
AGGRESSIVE_EXTRA_S = 75   # +sqli/xss/ssrf/path/upload/etc when --aggressive
PROVE_EXTRA_S = 25        # +read-only proof extraction when --prove
AUTH_EXTRA_S = 30         # +authenticated.py if creds provided


def estimate_scan_seconds(
    *,
    aggressive: bool = False,
    prove: bool = False,
    deep_throttle: bool = False,
    deep_throttle_attempts: int = 120,
    deep_throttle_pacing_s: float = 10.0,
    authenticated: bool = False,
) -> int:
    """Return a rough total-scan-time estimate in seconds.

    Always-on overhead + per-toggle additions + the deep-throttle wall-clock
    (which dominates whenever it's enabled)."""
    total = PASSIVE_TOTAL_S
    if aggressive:
        total += AGGRESSIVE_EXTRA_S
    if prove:
        total += PROVE_EXTRA_S
    if authenticated:
        total += AUTH_EXTRA_S
    if deep_throttle:
        total += int(deep_throttle_attempts * deep_throttle_pacing_s)
    return int(total)


def format_eta(seconds: int) -> str:
    """Human-friendly: '45s', '2m 30s', '24m', '1h 5m'."""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        if s == 0 or m >= 5:
            return f"{m}m"
        return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    return f"{h}h {m}m" if m else f"{h}h"
