"""#85-87 — Performance helpers (post-v2.8.0 T4).

T4 (v2.8.0) — removed three dead items:
  - #83 HTTP/3 client (has_http3) — never wired; aioquic is heavy
    and no production check uses it. Re-add when there's a caller.
  - #84 GPU-accelerated regex — was a documented stub since v2.5,
    never implemented; deferred indefinitely (CUDA dep too heavy
    for a defensive scanner shipped as a stand-alone PyInstaller
    .exe). Remove the placeholder comment.
  - #86 Worker-pool mode (worker_pool_scan) — never wired; the
    daemon's per-cron concurrency and perf_v27.scan_zip_parallel_
    paths cover the realistic fan-out use cases.

Surviving:
  #85 Bloom filter for already-scanned URLs (spider dedupe)
  #87 Per-check memoization — cache outputs by response-hash
"""
from __future__ import annotations

import hashlib


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


# T4 (v2.8.0) — `worker_pool_scan` (#86) and `has_http3` (#83) deleted
# as dead code (zero production callers). See module docstring.
