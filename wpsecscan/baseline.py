"""Baseline calibration for differential checks.

Sites with rotating ads, recommendation widgets, or A/B tests produce naturally
different responses between identical requests, which kills differential SQLi
detection (truthy vs falsy length comparison). This module establishes the
"natural noise floor" so checks can require a payload-induced delta that
exceeds it by a configurable margin.
"""
from __future__ import annotations

from dataclasses import dataclass

from .http import Client


@dataclass
class Baseline:
    path: str
    samples: int            # how many we successfully fetched
    avg_bytes: int          # mean body length
    max_delta_ratio: float  # max observed length-variance between samples (0..1)
    status_code: int

    def is_unstable(self, threshold: float = 0.08) -> bool:
        """Sites where two identical requests differ by >threshold are flaky baselines."""
        return self.max_delta_ratio > threshold


async def calibrate(client: Client, path: str = "/", params: dict | None = None, samples: int = 3) -> Baseline:
    """Issue `samples` identical requests, measure variance."""
    sizes: list[int] = []
    status = 0
    for _ in range(samples):
        r = await client.get(path, params=params)
        if r is None:
            continue
        status = r.status_code
        sizes.append(len(r.content or b""))
    if not sizes:
        return Baseline(path=path, samples=0, avg_bytes=0, max_delta_ratio=1.0, status_code=0)
    avg = sum(sizes) // len(sizes)
    if avg == 0:
        return Baseline(path=path, samples=len(sizes), avg_bytes=0, max_delta_ratio=0.0, status_code=status)
    # max pairwise variance / average
    spread = (max(sizes) - min(sizes)) / avg
    return Baseline(
        path=path,
        samples=len(sizes),
        avg_bytes=avg,
        max_delta_ratio=spread,
        status_code=status,
    )
