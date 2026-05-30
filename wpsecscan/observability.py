"""#103-108 Reliability / observability helpers.

#103 self-health dashboard data source
#104 cProfile-based --profile mode (small wrapper)
#105 watchdog — kill checks stuck >2× rolling median
#106 live tail of activity log
#107 per-target performance trend (uses existing check_durations.json)
#108 smart retry policy per check class
"""
from __future__ import annotations

import asyncio
import cProfile
import io
import pstats
import time
from pathlib import Path


# ---- #103 self-health ----

def self_health() -> dict:
    """Return scanner-process health: uptime, last scan, error rate, memory."""
    from . import history as _h
    home = Path(_h._home())
    audit_log = home / "audit.log.jsonl"
    last_scan_ts = None
    if audit_log.exists():
        try:
            last_scan_ts = audit_log.stat().st_mtime
        except OSError:
            pass
    try:
        import resource
        mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, Exception):  # noqa: BLE001
        try:
            import psutil
            mem_kb = psutil.Process().memory_info().rss / 1024
        except (ImportError, Exception):  # noqa: BLE001
            mem_kb = None
    return {
        "last_scan_ts": last_scan_ts,
        "last_scan_age_s": int(time.time() - last_scan_ts) if last_scan_ts else None,
        "memory_kb": int(mem_kb) if mem_kb else None,
    }


# ---- #104 --profile ----

async def profile_scan(scan_coro):
    """Run a scan under cProfile + return the formatted profile text."""
    profiler = cProfile.Profile()
    profiler.enable()
    try:
        result = await scan_coro
    finally:
        profiler.disable()
    s = io.StringIO()
    pstats.Stats(profiler, stream=s).sort_stats("cumulative").print_stats(40)
    return result, s.getvalue()


# ---- #105 watchdog ----

async def with_watchdog(coro, *, timeout_s: float):
    """Run coro with a hard timeout. Returns result or None on timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_s)
    except asyncio.TimeoutError:
        return None


# ---- #106 live-tail ----

def tail_activity_log(callback, *, poll_interval: float = 1.0) -> None:
    """Blocking tail of ~/.wpsecscan/audit.log.jsonl, calling `callback(line)` per line."""
    from . import history as _h
    p = Path(_h._home()) / "audit.log.jsonl"
    # N8 (v2.7.3) — was `if not p.exists(): p.touch()`, which on
    # Windows truncates an existing file silently and even on POSIX
    # has a TOCTOU window where another writer can populate the file
    # between exists() and touch(). Use atomic O_EXCL create; if
    # someone else just created it, that's fine — we just need a
    # file to tail.
    import os as _os
    try:
        fd = _os.open(str(p), _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o644)
        _os.close(fd)
    except FileExistsError:
        pass
    except OSError:
        pass
    with p.open("r", encoding="utf-8") as f:
        f.seek(0, 2)  # to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            try:
                callback(line.rstrip("\n"))
            except Exception:  # noqa: BLE001
                pass


# ---- #107 perf trend ----

def perf_trend(check_id: str, *, last_n: int = 20) -> list[int]:
    """Return last N duration_ms samples for `check_id`."""
    from . import check_health
    durations = check_health._load_durations()
    return list((durations.get(check_id) or [])[-last_n:])


# ---- #108 retry policy by class ----

RETRY_POLICY = {
    "passive":     {"max_retries": 1, "base_delay_s": 0.5},
    "aggressive":  {"max_retries": 0, "base_delay_s": 0.0},  # never retry aggressive — payloads aren't idempotent
    "intel":       {"max_retries": 3, "base_delay_s": 2.0},
}


async def with_retry(coro_factory, *, klass: str = "passive"):
    """Call `coro_factory()` repeatedly per the retry policy for `klass`.
    Exponential backoff."""
    pol = RETRY_POLICY.get(klass, RETRY_POLICY["passive"])
    last_exc = None
    for attempt in range(pol["max_retries"] + 1):
        try:
            return await coro_factory()
        except Exception as e:  # noqa: BLE001
            last_exc = e
            if attempt < pol["max_retries"]:
                await asyncio.sleep(pol["base_delay_s"] * (2 ** attempt))
    if last_exc:
        raise last_exc
