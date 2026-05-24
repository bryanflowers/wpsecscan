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


async def run_daemon(config_path: Path) -> None:
    """Main daemon loop. Wakes up every 30 seconds and triggers matching cron jobs."""
    config = _load_config(config_path)
    targets = config.get("targets") or []
    out_dir = Path(config.get("out_dir") or "./reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    webhook_url = config.get("webhook_url") or ""

    from .scanner import scan
    from .reporters import json_out, html as html_reporter
    from wpsecscan import notify as _n

    print(f"[daemon] loaded {len(targets)} target(s) from {config_path}")
    print(f"[daemon] output dir: {out_dir.resolve()}")
    print("[daemon] sleeping until next cron match...")

    last_minute_run: set[tuple[str, str]] = set()  # (url, minute-key) to avoid double-firing

    while True:
        now = datetime.now()
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
                    (out_dir / f"{stem}.json").write_text(json_out.render(report), encoding="utf-8")
                    (out_dir / f"{stem}.html").write_text(html_reporter.render(report), encoding="utf-8")
                    print(f"[daemon] {url} done; risk score {report.risk_score}; wrote {stem}.[json|html]")
                    if webhook_url:
                        _n.notify(report, webhook_url, threshold=t.get("fail_on") or "high")
                except Exception as e:  # noqa: BLE001
                    print(f"[daemon] ERROR scanning {url}: {e}")
        # Keep last_minute_run from growing unbounded — drop entries older than 2 min
        cutoff = (datetime.now().strftime("%Y-%m-%dT%H:%M"))
        last_minute_run = {entry for entry in last_minute_run if entry[1] >= cutoff}
        await asyncio.sleep(30)
