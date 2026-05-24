"""Performance helpers — Round-64 #164-165 + legacy #83-87 API.

Re-exports the original perf.py module symbols so callers that imported
`wpsecscan.perf.BloomFilter` etc. continue to work.
"""
from ._legacy import (  # noqa: F401
    BloomFilter,
    memoize_check,
    lookup_memo,
    worker_pool_scan,
    has_http3,
)
