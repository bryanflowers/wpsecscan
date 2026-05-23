"""L33 Hot-reload custom checks.

Calling `reload_custom_checks()` removes any previously-loaded plugins from
ALL_CHECKS and re-scans ~/.wpsecscan/plugins/ from disk. Useful in the GUI:
edit a plugin, click "Reload custom checks", run again — no restart.

The built-in checks are never touched.
"""
from __future__ import annotations

import sys

from . import checks as _checks_pkg


_USER_PLUGIN_PREFIX = "_wpsec_user_plugin_"


def loaded_plugin_count() -> int:
    """Return how many user plugins are currently in ALL_CHECKS."""
    return sum(1 for mod_name in list(sys.modules)
               if mod_name.startswith(_USER_PLUGIN_PREFIX))


def reload_custom_checks() -> tuple[int, int]:
    """Remove all user-plugin checks from ALL_CHECKS, then re-scan plugins dir.

    Returns (removed_count, added_count).
    """
    # 1. Drop any registered user-plugin checks. Identify by check_id collision
    #    with a previously-loaded user-plugin module.
    user_module_check_ids: set[str] = set()
    for mod_name in list(sys.modules):
        if not mod_name.startswith(_USER_PLUGIN_PREFIX):
            continue
        mod = sys.modules[mod_name]
        cid = getattr(mod, "CHECK_ID", None)
        if cid:
            user_module_check_ids.add(cid)
        # Drop from sys.modules so the next load re-execs the file
        del sys.modules[mod_name]

    before = len(_checks_pkg.ALL_CHECKS)
    _checks_pkg.ALL_CHECKS[:] = [
        entry for entry in _checks_pkg.ALL_CHECKS
        if entry[0] not in user_module_check_ids
    ]
    removed = before - len(_checks_pkg.ALL_CHECKS)

    # 2. Reset the one-shot guard and reload
    _checks_pkg._CUSTOM_CHECKS_LOADED = False
    _checks_pkg._load_custom_checks()

    added = len(_checks_pkg.ALL_CHECKS) - (before - removed)
    return removed, added
