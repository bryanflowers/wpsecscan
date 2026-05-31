"""Daemon mode — watch a YAML config + run scheduled scans.

Usage: `wpsecscan --daemon config.yml`. The config file shape:

```yaml
targets:
  - url: https://example.com
    schedule: "0 3 * * *"        # cron — daily at 3am
    aggressive: false
    fail_on: high
  - url: https://shop.example.com
    schedule: "0 */6 * * *"      # every 6 hours
    aggressive: true
    fail_on: critical
out_dir: /var/log/wpsecscan
webhook_url: https://hooks.slack.com/...
```

Light implementation — no system service install, just `python -m wpsecscan
--daemon config.yml &` and it loops. Cron parsed by a built-in mini-parser
(no croniter dependency).
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path


def _parse_cron_field(field: str, min_val: int, max_val: int) -> set[int]:
    """Parse a single cron field — supports *, N, N-M, */N. No L/# extensions.

    Raises ValueError on any value outside [min_val, max_val] so a typo like
    `"32"` in a day-of-month field fails loudly instead of silently never matching.
    """
    def _check(v: int) -> int:
        if v < min_val or v > max_val:
            raise ValueError(
                f"cron field value {v} out of range [{min_val},{max_val}]"
            )
        return v

    out: set[int] = set()
    for chunk in field.split(","):
        chunk = chunk.strip()
        if chunk == "*":
            return set(range(min_val, max_val + 1))
        if chunk.startswith("*/"):
            step = int(chunk[2:])
            if step <= 0:
                raise ValueError(f"cron field step {step!r} must be positive")
            out.update(range(min_val, max_val + 1, step))
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ai, bi = _check(int(a)), _check(int(b))
            if ai > bi:
                raise ValueError(f"cron field range {chunk!r} has start > end")
            out.update(range(ai, bi + 1))
            continue
        out.add(_check(int(chunk)))
    return out


def _cron_matches(expr: str, dt: datetime) -> bool:
    """Return True if `dt` matches the 5-field cron `expr`."""
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    minute, hour, day, month, dow = parts
    return (
        dt.minute in _parse_cron_field(minute, 0, 59)
        and dt.hour in _parse_cron_field(hour, 0, 23)
        and dt.day in _parse_cron_field(day, 1, 31)
        and dt.month in _parse_cron_field(month, 1, 12)
        and (dt.weekday() + 1) % 7 in _parse_cron_field(dow, 0, 6)
    )


def _load_config(path: Path) -> dict:
    """Parse the YAML config — minimal home-grown parser to avoid pyyaml dep.

    Supports the exact shape documented in the module docstring; not full YAML.
    For complex configs, the user should install pyyaml + we'd use it if present.
    """
    try:
        import yaml  # type: ignore[import-not-found]
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except ImportError:
        pass
    # Minimal hand-rolled parser for the documented shape (list of dicts under `targets:`)
    import json
    # If the file is actually JSON, accept it
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    raise RuntimeError(
        f"Couldn't parse {path}: install `pyyaml` or supply the config as JSON."
    )


def _acquire_pid_file() -> Path | None:
    """v2.8.1 B35 — write a PID file at ~/.wpsecscan/daemon.pid with
    atomic O_CREAT|O_EXCL semantics. If the file already exists, probe
    the recorded PID — if the process is dead, the lock is stale and
    we steal it; if alive, refuse to start.

    Returns the PID-file Path on success, None on lock-conflict.
    """
    import os as _os
    from wpsecscan.history import _home as _wh_home
    pid_path = _wh_home() / "daemon.pid"
    try:
        fd = _os.open(str(pid_path),
                       _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        with _os.fdopen(fd, "w") as fh:
            fh.write(str(_os.getpid()))
        return pid_path
    except FileExistsError:
        # Probe the existing PID for liveness.
        try:
            existing_pid = int((pid_path.read_text(encoding="utf-8") or "0").strip())
        except (OSError, ValueError):
            existing_pid = 0
        is_alive = False
        if existing_pid > 0:
            try:
                _os.kill(existing_pid, 0)  # signal 0 = liveness probe
                is_alive = True
            except (OSError, ProcessLookupError):
                is_alive = False
        if is_alive:
            print(f"[daemon] another daemon is already running "
                  f"(pid {existing_pid} from {pid_path}); refusing to start.",
                  file=__import__("sys").stderr)
            return None
        # Stale lock — steal it.
        try:
            pid_path.unlink()
        except OSError:
            pass
        try:
            fd = _os.open(str(pid_path),
                           _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
            with _os.fdopen(fd, "w") as fh:
                fh.write(str(_os.getpid()))
            print(f"[daemon] reclaimed stale PID file (was pid {existing_pid}).")
            return pid_path
        except OSError:
            return None
    except OSError:
        return None


async def run_daemon(config_path: Path) -> None:
    """Main daemon loop. Wakes up every 30 seconds and triggers matching cron jobs."""
    # v2.8.1 B35 — refuse to start if another daemon already holds
    # the PID file (atomic lock; stale-lock detection via os.kill).
    pid_path = _acquire_pid_file()
    if pid_path is None:
        import sys as _sys
        _sys.exit(75)  # EX_TEMPFAIL — operator should retry after killing the other instance

    config = _load_config(config_path)
    targets = config.get("targets") or []
    out_dir = Path(config.get("out_dir") or "./reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    webhook_url = config.get("webhook_url") or ""

    from .scanner import scan
    from .reporters import json_out, html as html_reporter
    from wpsecscan import notify as _n
    from wpsecscan.history import _atomic_write_text as _atomic

    print(f"[daemon] loaded {len(targets)} target(s) from {config_path}")
    print(f"[daemon] output dir: {out_dir.resolve()}")
    print("[daemon] sleeping until next cron match...")

    # B5 (v2.8.0) — install SIGTERM/SIGHUP handlers so docker stop /
    # systemd Restart and logrotate's SIGHUP don't kill the process
    # mid-scan. asyncio's loop.add_signal_handler is the right way to
    # cooperate with the await asyncio.sleep below; on Windows
    # add_signal_handler raises NotImplementedError so we fall back
    # to signal.signal there. The cancel-on-signal pattern lets the
    # current scan complete then exit cleanly at the next loop check.
    import signal as _signal
    _shutdown = asyncio.Event()

    def _request_shutdown(*_a):
        print("[daemon] shutdown signal received; finishing current scan...")
        _shutdown.set()

    try:
        loop = asyncio.get_running_loop()
        for _sig in (_signal.SIGTERM, _signal.SIGHUP) if hasattr(_signal, "SIGHUP") else (_signal.SIGTERM,):
            try:
                loop.add_signal_handler(_sig, _request_shutdown)
            except (NotImplementedError, RuntimeError):
                _signal.signal(_sig, _request_shutdown)
    except RuntimeError:
        pass  # not in an asyncio loop; signal handlers stay default

    last_minute_run: set[tuple[str, str]] = set()  # (url, minute-key) to avoid double-firing

    while not _shutdown.is_set():
        # B47 (v2.8.0) — was: datetime.now() (local time). Servers in
        # non-UTC zones (or after a DST transition) fired cron at the
        # wrong wall-clock time. Use UTC consistently — operators who
        # want local-time cron should rely on _cron_matches accepting
        # a TZ-aware datetime if/when that's added in v2.8.1.
        from datetime import timezone as _tz
        now = datetime.now(_tz.utc).replace(tzinfo=None)
        minute_key = now.strftime("%Y-%m-%dT%H:%M")
        for t in targets:
            url = t.get("url")
            schedule = t.get("schedule") or ""
            if not url or not schedule:
                continue
            if (url, minute_key) in last_minute_run:
                continue
            if _cron_matches(schedule, now):
                last_minute_run.add((url, minute_key))
                print(f"[daemon] {now.isoformat(timespec='seconds')} firing scan for {url}")
                try:
                    report = await scan(
                        url,
                        aggressive=bool(t.get("aggressive")),
                        timeout=float(t.get("timeout") or 15.0),
                        concurrency=int(t.get("concurrency") or 10),
                    )
                    stem = url.replace("://", "_").replace("/", "_") + "_" + now.strftime("%Y%m%d_%H%M%S")
                    # B4 (v2.8.0) — atomic temp+replace so a SIGTERM
                    # or crash mid-write leaves no torn file. Mirrors
                    # the history._atomic_write_text helper added in
                    # v2.7.3 for siblings in history.py.
                    _atomic(out_dir / f"{stem}.json", json_out.render(report))
                    _atomic(out_dir / f"{stem}.html", html_reporter.render(report))
                    print(f"[daemon] {url} done; risk score {report.risk_score}; wrote {stem}.[json|html]")
                    if webhook_url:
                        _n.notify(report, webhook_url, threshold=t.get("fail_on") or "high")
                except Exception as e:  # noqa: BLE001
                    print(f"[daemon] ERROR scanning {url}: {e}")
        # B48 (v2.8.0) — comment said "drop older than 2 min" but the
        # code only retained CURRENT-minute entries. Practical effect
        # was a no-op cleanup that happened to work because the dedup
        # only mattered within one minute. Make the comment match
        # reality and bound the set explicitly to one minute back
        # so DST-rollover edge cases don't accidentally re-fire.
        cutoff_dt = datetime.now(_tz.utc).replace(tzinfo=None)
        cutoff = cutoff_dt.strftime("%Y-%m-%dT%H:%M")
        last_minute_run = {entry for entry in last_minute_run if entry[1] >= cutoff}
        await asyncio.sleep(30)
