"""Incremental scan helpers — Round-64 #162-163 + legacy K26/K27 API.

Re-exports the original incremental.py module symbols so callers that
imported `wpsecscan.incremental.should_skip_check` etc. continue to work.
"""
from ._legacy import (  # noqa: F401
    LOW_CHURN_CHECK_IDS,
    has_target_changed,
    should_skip_check,
    record_observation,
    anomaly_for,
    _load_baseline as load_baseline,
    _save_baseline as save_baseline,
    _snapshot_dir,
    _baseline_path,
    _latest_snapshot_for,
)
