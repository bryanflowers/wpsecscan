"""Performance helpers — Round-64 #164-165 + legacy #83-87 API.

Re-exports the original perf.py module symbols so callers that imported
`wpsecscan.perf.BloomFilter` etc. continue to work.

T4 (v2.8.0) — removed dead `worker_pool_scan` and `has_http3`
re-exports. Both had zero production callers (per the v2.7.3 Agent I
I6 finding) and have been deleted along with their definitions in
`_legacy.py`. Future callers wanting concurrent scan-pooling should
use the existing `wpsecscan.perf_v27.scan_zip_parallel_paths` (or
the daemon's per-cron concurrency) instead.
"""
from ._legacy import (  # noqa: F401
    BloomFilter,
    memoize_check,
    lookup_memo,
)
