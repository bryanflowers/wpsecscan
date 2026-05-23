"""#34 (from turbo-intruder) — response diffing across N requests.

Given a list of response summaries from `turbo_engine.burst` /
`.last_byte_sync`, compute statistical features and flag outliers.
Useful for attacks where the "interesting" response is the one that
behaves differently from the rest.

Features computed per response:
  - status_code
  - body_length
  - distinct_word_count (rough complexity proxy)
  - response_hash (sha1 of body bytes — collisions are interesting)

Outlier detection: any response whose status differs from the modal
status, or whose body_length is more than 2σ from the mean, OR whose
hash differs from the majority hash.
"""
from __future__ import annotations

import hashlib
import statistics
from collections import Counter


def fingerprint(response_dict: dict) -> dict:
    """Add hash + word-count to a response summary in place."""
    body = response_dict.get("body") or b""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    response_dict["body_len"] = response_dict.get("len") or len(body)
    if body:
        response_dict["body_hash"] = hashlib.sha1(body).hexdigest()[:16]
        try:
            response_dict["word_count"] = len((body.decode("utf-8", errors="replace")).split())
        except (UnicodeDecodeError, AttributeError):
            response_dict["word_count"] = 0
    else:
        response_dict["body_hash"] = ""
        response_dict["word_count"] = 0
    return response_dict


def diff(responses: list[dict]) -> dict:
    """Identify outliers. Returns a summary dict with `outliers` (indices)
    and `notes` (strings explaining what's unusual)."""
    if not responses:
        return {"outliers": [], "notes": []}

    statuses = [r.get("status", 0) for r in responses]
    modal_status, _ = Counter(statuses).most_common(1)[0]
    lengths = [int(r.get("len") or r.get("body_len") or 0) for r in responses]
    hashes = [r.get("body_hash", "") for r in responses]
    modal_hash, _ = Counter(hashes).most_common(1)[0] if hashes else ("", 0)

    mean_len = statistics.mean(lengths) if lengths else 0
    stdev_len = statistics.stdev(lengths) if len(lengths) > 1 else 0

    outliers: list[int] = []
    notes: list[str] = []
    for i, r in enumerate(responses):
        reasons = []
        if r.get("status", 0) != modal_status:
            reasons.append(f"status {r.get('status')} vs modal {modal_status}")
        l = int(r.get("len") or r.get("body_len") or 0)
        if stdev_len > 0 and abs(l - mean_len) > 2 * stdev_len:
            reasons.append(f"body len {l} vs mean {int(mean_len)} (±{int(2*stdev_len)})")
        h = r.get("body_hash", "")
        if h and modal_hash and h != modal_hash:
            reasons.append(f"body hash differs from majority ({h} vs {modal_hash})")
        if reasons:
            outliers.append(i)
            notes.append(f"  request {i}: " + "; ".join(reasons))

    return {
        "n": len(responses),
        "modal_status": modal_status,
        "mean_len": int(mean_len),
        "stdev_len": int(stdev_len),
        "outliers": outliers,
        "notes": notes,
    }
