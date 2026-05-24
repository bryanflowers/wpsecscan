"""Daemon helpers — Round-64 #146 (webhook v2) + legacy daemon-mode API.

Re-exports the original daemon.py module symbols so callers that
imported `wpsecscan.daemon._parse_cron_field` etc. continue to work.
"""
from ._legacy import (  # noqa: F401
    _parse_cron_field,
    _cron_matches,
    _load_config,
)
