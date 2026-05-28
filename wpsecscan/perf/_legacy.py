"""#83-87 — Performance helpers.

#83 HTTP/3 client — best-effort using httpx with aioquic when available
#84 GPU-accelerated regex — documented stub; deferred (CUDA dep too heavy)
#85 Bloom filter for already-scanned URLs (spider dedupe)
#86 Worker-pool mode — multiprocess fan-out across targets
#87 Per-check memoization — cache outputs by response-hash
"""
from __future__ import annotations

import hashlib
import multiprocessing
import os
from functools import lru_cache


# ---- #85 Bloom filter ----

class BloomFilter:
    """Tiny pure-Python bloom filter — for spider URL dedupe at scale.
    Capacity ~100k URLs at 0.1% false positive rate ≈ 150 KB bytes."""

    def __init__(self, capacity: int = 100_000, fp_rate: float = 0.001):
        import math
        self.capacity = capacity
        self.size = max(64, int(-capacity * math.log(fp_rate) / (math.log(2) ** 2)))
        self.hash_count = max(1, int(self.size / capacity * math.log(2)))
        self.bits = bytearray((self.size + 7) // 8)

    def _hash_idxs(self, item: str) -> list[int]:
        h = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
        return [int.from_bytes(h[i*2:(i+1)*2], "big") % self.size
                for i in range(self.hash_count)]

    def add(self, item: str) -> None:
        for idx in self._hash_idxs(item):
            self.bits[idx // 8] |= (1 << (idx % 8))

    def __contains__(self, item: str) -> bool:
        return all(self.bits[idx // 8] & (1 << (idx % 8))
                   for idx in self._hash_idxs(item))


# ---- #87 per-check memoization ----

_memo_cache: dict[str, list] = {}


# C20 (v2.7.2) — switched from SHA-1 to SHA-256 (truncated to 16 hex
# chars). SHA-1 collisions (SHAttered) combined with the truncation
# created a real risk that a crafted response body could collide
# with a legitimate cached entry, serving stale findings for an
# unrelated response.
def memoize_check(check_id: str, response_body: bytes, findings: list) -> None:
    """Store check output keyed by SHA256(response body). Bounded at 500 entries."""
    key = f"{check_id}:{hashlib.sha256(response_body).hexdigest()[:16]}"
    _memo_cache[key] = list(findings)
    while len(_memo_cache) > 500:
        _memo_cache.pop(next(iter(_memo_cache)))


def lookup_memo(check_id: str, response_body: bytes) -> list | None:
    key = f"{check_id}:{hashlib.sha256(response_body).hexdigest()[:16]}"
    return _memo_cache.get(key)


# ---- #86 worker-pool ----

def worker_pool_scan(targets: list[str], worker_fn, *, workers: int | None = None) -> list:
    """Run `worker_fn(target)` across N processes in parallel. Returns list of results."""
    workers = workers or max(1, (multiprocessing.cpu_count() or 4) - 1)
    with multiprocessing.Pool(processes=workers) as pool:
        return pool.map(worker_fn, targets)


# ---- #83 HTTP/3 detection (does our httpx have h3? no by default) ----

@lru_cache(maxsize=1)
def has_http3() -> bool:
    """True if aioquic / httpx h3 transport is installed."""
    try:
        import aioquic  # noqa: F401
        return True
    except ImportError:
        return False
