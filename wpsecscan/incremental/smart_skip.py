"""Smart-skip — skip checks that have no chance of firing.

Round-64 #163 — e.g. don't run wpgraphql checks when GraphQL isn't
installed. Maintains a per-target "applicability map" derived from
fingerprints. Saves ~20-40% wall time on small sites.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _path(target: str) -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    safe = "".join(c if c.isalnum() else "_" for c in target)
    return home / "incremental" / safe / "applicability.json"


def load(target: str) -> dict:
    p = _path(target)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(target: str, data: dict) -> None:
    p = _path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


# Mapping check_id -> ctx-shared key that must be truthy for the check to fire
# (populated by fingerprint checks running early in the scan).
_PRECONDITIONS = {
    "wpgraphql":                "has_graphql",
    "graphql_dos":              "has_graphql",
    "graphql_field_dos":        "has_graphql",
    "graphql_field_authz_deep": "has_graphql",
    "woocommerce_audit":        "has_woocommerce",
    "woocommerce_deep":         "has_woocommerce",
    "wp_query_sqli":            "has_woocommerce",  # Plugin-CVE heavy
    "crypto_payment_callback_audit": "has_woocommerce",
    "multisite":                "is_multisite",
    "wp_multisite_deep":        "is_multisite",
    "headless_wp_audit":        "is_headless",
}


def should_skip(check_id: str, shared: dict) -> tuple[bool, str]:
    """Returns (skip, reason)."""
    precond = _PRECONDITIONS.get(check_id)
    if not precond:
        return False, ""
    # If the precondition key is explicitly False (not absent), skip
    val = shared.get(precond)
    if val is False:
        return True, f"precondition {precond!r} is False"
    return False, ""


def remember_applicability(target: str, shared: dict) -> None:
    """Persist the detected applicability flags so subsequent scans can skip earlier."""
    flags = {k: bool(v) for k, v in shared.items() if k in set(_PRECONDITIONS.values())}
    if flags:
        save(target, flags)


def load_prior_applicability(target: str) -> dict:
    """Pre-seed shared dict with prior scan's flags for first-pass skipping."""
    return load(target)
