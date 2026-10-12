"""Incremental scan helpers — Round-64 #162-163 + legacy K26/K27 API.

Re-exports the original incremental.py module symbols so callers that
imported `wpsecscan.incremental.should_skip_check` etc. continue to work.
"""
from ._legacy import (  # noqa: F401
    LOW_CHURN_CHECK_IDS,
    _baseline_path,
    _latest_snapshot_for,
    _snapshot_dir,
    anomaly_for,
    has_target_changed,
    record_observation,
    should_skip_check,
)
from ._legacy import (
    _load_baseline as load_baseline,
)
from ._legacy import (
    _save_baseline as save_baseline,
)
