"""Round-62 #B26 + #G80 — Network egress recorder.

Logs every outbound IP + URL + timestamp the scanner hits during a scan.
Useful for:
  - defensive intelligence ("during the scan, my tool reached these CDNs")
  - compliance audit trail
  - PII / data-egress proof for GDPR DPAs
  - troubleshooting (which 3rd party CVE feed failed?)

Used via Client wrapper hooks. Records to ~/.wpsecscan/egress-<host>.jsonl.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlparse


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _egress_dir() -> Path:
    d = _home() / "egress"
    d.mkdir(parents=True, exist_ok=True)
    return d


_LOCK = threading.Lock()
_ACTIVE_PATH: Path | None = None


def start_recording(target: str) -> Path:
    """Begin a recording session for `target`. Returns the path being written to."""
    global _ACTIVE_PATH
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", urlparse(target).hostname or "scan")[:80]
    p = _egress_dir() / f"egress-{safe}-{int(time.time())}.jsonl"
    if p.is_symlink():
        try:
            p.unlink()
        except OSError:
            pass
    _ACTIVE_PATH = p
    return p


def record(url: str, *, method: str = "GET", status: int | None = None,
            ip: str | None = None, took_ms: int | None = None) -> None:
    """Append one egress event. No-op if recording isn't started."""
    if _ACTIVE_PATH is None:
        return
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not ip and host:
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            ip = ""
    entry = {
        "ts":     int(time.time()),
        "method": method,
        "host":   host,
        "ip":     ip or "",
        "path":   parsed.path[:200],
        "status": status,
        "took_ms": took_ms,
    }
    with _LOCK:
        try:
            # Round-62 QA: cap at 50 MB so a 24h scan can't fill the disk.
            # Rollover to .<ts>.archived once exceeded.
            if _ACTIVE_PATH.exists() and _ACTIVE_PATH.stat().st_size > 50_000_000:
                archived = _ACTIVE_PATH.with_suffix(
                    _ACTIVE_PATH.suffix + f".{int(time.time())}.archived")
                try:
                    _ACTIVE_PATH.rename(archived)
                except OSError:
                    pass
            with _ACTIVE_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def stop_recording() -> Path | None:
    """End recording. Returns the file path written, or None if not started."""
    global _ACTIVE_PATH
    p = _ACTIVE_PATH
    _ACTIVE_PATH = None
    return p


def summarise(path: Path | str) -> dict:
    """Return {total, unique_hosts, unique_ips, top10_hosts, geo_breakdown(stub)}."""
    p = Path(path)
    if not p.exists() or p.is_symlink():
        return {}
    hosts: dict[str, int] = {}
    ips: set = set()
    total = 0
    try:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                h = e.get("host", "")
                if h:
                    hosts[h] = hosts.get(h, 0) + 1
                if e.get("ip"):
                    ips.add(e["ip"])
    except OSError:
        return {}
    top = sorted(hosts.items(), key=lambda kv: -kv[1])[:10]
    return {
        "total":         total,
        "unique_hosts":  len(hosts),
        "unique_ips":    len(ips),
        "top10_hosts":   top,
    }
