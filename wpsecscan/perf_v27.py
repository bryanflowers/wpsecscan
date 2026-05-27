"""v2.7.0 performance / scale (I110-I115).

  I110 cmd_worker(args)            — Redis-queue distributed scan worker.
  I111 etag_cache get/set          — conditional-GET cache used by http.Client.
  I112 timeout_for(check_id)        — per-check timeout via env var.
  I113 (already shipped)            — adaptive throttle in http.py.
  I114 prewarm_dns(host)            — async DNS resolution at scan-start.
  I115 scan_zip_parallel(zip_path)  — concurrent PHP file walk.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from ._util import home_dir


# ---------------------------------------------------------------------------
# I110 — Redis queue worker
# ---------------------------------------------------------------------------

def cmd_worker(args: list[str]) -> None:
    """`wpsecscan worker [--queue wpsecscan:urls] [--out OUTPUT_DIR]`

    Connects to Redis (via REDIS_URL env var) and pops URLs from a list,
    scanning each one. Lets N machines share a portfolio without a
    central scheduler. Long-running; Ctrl+C to stop.
    """
    if args and args[0] in ("-h", "--help"):
        print("usage: wpsecscan worker [--queue wpsecscan:urls] [--out DIR]",
              file=sys.stderr)
        return
    try:
        import redis  # type: ignore[import-not-found]
    except ImportError:
        print("install redis: pip install redis", file=sys.stderr); sys.exit(2)
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    queue = "wpsecscan:urls"
    out_dir = Path("./wpsec-worker-out")
    i = 0
    while i < len(args):
        if args[i] == "--queue" and i + 1 < len(args):
            queue = args[i + 1]; i += 2
        elif args[i] == "--out" and i + 1 < len(args):
            out_dir = Path(args[i + 1]); i += 2
        else:
            i += 1
    out_dir.mkdir(parents=True, exist_ok=True)
    r = redis.from_url(url)
    print(f"[worker] connected to {url}; popping from queue '{queue}' (Ctrl+C to stop)")
    import subprocess
    while True:
        try:
            popped = r.brpop(queue, timeout=10)
        except Exception as e:  # noqa: BLE001
            print(f"[worker] redis error: {e}", file=sys.stderr); time.sleep(5); continue
        if not popped:
            continue
        target = popped[1].decode("utf-8", errors="replace").strip()
        if not target:
            continue
        print(f"[worker] scanning {target}")
        try:
            subprocess.run(
                [sys.executable, "-m", "wpsecscan", target, "--out", str(out_dir),
                  "--no-console", "--json-only", "--no-update-check"],
                capture_output=True, timeout=600,
            )
        except subprocess.TimeoutExpired:
            print(f"[worker] timed out: {target}", file=sys.stderr)


# ---------------------------------------------------------------------------
# I111 — Conditional-GET / ETag cache (used by http.Client when enabled)
# ---------------------------------------------------------------------------

def _etag_db_path() -> Path:
    return home_dir() / "etag-cache.json"


def etag_get(url: str) -> tuple[str, str] | None:
    """Return (etag, last_modified) for a previously-seen URL."""
    try:
        db = json.loads(_etag_db_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = db.get(url) if isinstance(db, dict) else None
    if not isinstance(entry, dict):
        return None
    return (entry.get("etag", ""), entry.get("last_modified", ""))


def etag_set(url: str, etag: str, last_modified: str) -> None:
    """Store the ETag + Last-Modified for a URL after a successful GET."""
    try:
        db = json.loads(_etag_db_path().read_text(encoding="utf-8")) \
                if _etag_db_path().exists() else {}
    except (OSError, ValueError):
        db = {}
    if not isinstance(db, dict):
        db = {}
    # Cap the cache at 5k entries to avoid unbounded growth
    if len(db) > 5000:
        db = dict(list(db.items())[-2500:])
    db[url] = {"etag": etag, "last_modified": last_modified, "ts": int(time.time())}
    p = _etag_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(db), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# I112 — Per-check timeout via env var
# ---------------------------------------------------------------------------

def timeout_for(check_id: str, default: float = 30.0) -> float:
    """Return the per-check timeout (seconds). Reads
    WPSECSCAN_CHECK_TIMEOUT_<UPPER_CHECK_ID> first, else
    WPSECSCAN_DEFAULT_CHECK_TIMEOUT, else `default`."""
    specific = os.environ.get(f"WPSECSCAN_CHECK_TIMEOUT_{check_id.upper()}")
    if specific:
        try:
            return float(specific)
        except ValueError:
            pass
    generic = os.environ.get("WPSECSCAN_DEFAULT_CHECK_TIMEOUT")
    if generic:
        try:
            return float(generic)
        except ValueError:
            pass
    return default


# ---------------------------------------------------------------------------
# I114 — Pre-warm DNS resolution
# ---------------------------------------------------------------------------

async def prewarm_dns(host: str) -> bool:
    """Async DNS resolution that primes the OS resolver cache before the
    scanner's first connection. Returns True on success."""
    if not host:
        return False
    try:
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo(host, 443)
        return True
    except (OSError, Exception):  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# I115 — scan-zip parallel PHP-file walk
# ---------------------------------------------------------------------------

def scan_zip_parallel_paths(php_files: list[Path], pattern_re_list,
                              *, workers: int = 4) -> list[tuple[Path, int, int, str]]:
    """Parallelise the per-file regex scan from scan_zip.py. Returns a
    list of (path, rx_index, byte_offset, match_text) tuples. The
    caller maps these to Finding objects using the original regex
    severity mapping."""
    import concurrent.futures
    results: list[tuple[Path, int, int, str]] = []

    def _scan(php_path: Path) -> list[tuple[Path, int, int, str]]:
        hits: list[tuple[Path, int, int, str]] = []
        try:
            text = php_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return hits
        for rx_idx, rx in enumerate(pattern_re_list):
            for m in rx.finditer(text):
                hits.append((php_path, rx_idx, m.start(), m.group(0)[:200]))
        return hits

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for batch in ex.map(_scan, php_files):
            results.extend(batch)
    return results
