"""Distributed scan coordinator via Redis queue.

Round-64 #160 — split a multi-site scan across N workers. Each worker
pops a `(tenant, site, scan_id)` from `wpsecscan:scan_queue`, runs the
scan, then pushes results to `wpsecscan:scan_results`. Coordinator
collects results + emits the final report.

Stub — requires redis-py. Real deployment uses RQ or Celery for
robustness; this module is the minimum viable shape.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class ScanJob:
    job_id: str
    tenant_id: str
    target: str
    aggressive: bool = False
    submitted_at: float = 0.0


def _redis():
    """Lazy import so the module is loadable without redis installed."""
    try:
        import redis  # type: ignore
    except ImportError as e:
        raise ImportError("pip install redis required for distributed coordinator") from e
    import os
    url = os.environ.get("WPSECSCAN_REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(url, decode_responses=True)


def enqueue(job: ScanJob) -> None:
    r = _redis()
    job.submitted_at = job.submitted_at or time.time()
    r.lpush("wpsecscan:scan_queue", json.dumps(asdict(job)))


def dequeue(timeout: int = 5) -> ScanJob | None:
    r = _redis()
    item = r.brpop("wpsecscan:scan_queue", timeout=timeout)
    if item is None:
        return None
    _, payload = item
    return ScanJob(**json.loads(payload))


def push_result(job_id: str, result: dict[str, Any]) -> None:
    r = _redis()
    r.hset("wpsecscan:scan_results", job_id, json.dumps(result))
    r.publish("wpsecscan:result_events", job_id)


def get_result(job_id: str) -> dict[str, Any] | None:
    r = _redis()
    raw = r.hget("wpsecscan:scan_results", job_id)
    return json.loads(raw) if raw else None


def queue_depth() -> int:
    return int(_redis().llen("wpsecscan:scan_queue"))


# Worker loop skeleton — actual integration with wpsecscan.scanner
# happens in the daemon.
def worker_loop(scan_fn, *, worker_id: str = "w1") -> None:
    """`scan_fn(job) -> dict` is the actual scan implementation."""
    while True:
        job = dequeue(timeout=5)
        if job is None:
            continue
        try:
            result = scan_fn(job)
            result["worker_id"] = worker_id
            push_result(job.job_id, result)
        except Exception as e:  # noqa: BLE001
            push_result(job.job_id, {"error": str(e), "worker_id": worker_id})
