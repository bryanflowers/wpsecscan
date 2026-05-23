"""#33 (from turbo-intruder) — Python attack-script runner.

WPSecScan already supports Python plugin checks (see plugin_scaffold.py).
This module adds a higher-level "attack script" mode that gives the user
direct access to `turbo_engine.burst` / `.last_byte_sync` / `.single_packet_h2`
plus a `Finding` constructor.

Scripts live in `~/.wpsecscan/attacks/*.py`. Each script exports:

    ATTACK_ID = "my_attack"
    ATTACK_NAME = "My attack"

    def run(target, engine, Finding):
        # `engine` is the turbo_engine module
        results = engine.last_byte_sync(target + "/?action=apply_coupon",
                                          n=30, method="POST",
                                          body=b"coupon=FREE")
        statuses = [r.get("status", 0) for r in results]
        accepted = sum(1 for s in statuses if 200 <= s < 300)
        if accepted > 1:
            return [Finding(
                severity="critical",
                title=f"Race condition: {accepted} parallel coupon claims accepted",
                evidence=f"Sent 30 parallel POSTs; {accepted} succeeded ({statuses}).",
                remediation="Add row-level locking on coupon redemption.",
                url=target,
            )]
        return []

Run via `wpsecscan --attack my_attack TARGET`.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Callable


def _attacks_dir() -> Path:
    from . import history as _h
    p = Path(_h._home()) / "attacks"
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_attacks() -> list[Path]:
    return sorted(_attacks_dir().glob("*.py"))


def load_attack(name: str):
    """Load `~/.wpsecscan/attacks/<name>.py` and return its module."""
    p = _attacks_dir() / f"{name}.py"
    if not p.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"_wpsec_attack_{name}", p)
    if not spec or not spec.loader:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001
        return None
    return mod


def run_attack(name: str, target: str) -> list:
    """Execute attack script `<name>` against `target`. Returns the
    list of Finding objects the script produced (may be empty)."""
    mod = load_attack(name)
    if mod is None or not hasattr(mod, "run"):
        return []
    from . import turbo_engine as _engine
    from .models import Finding
    try:
        return mod.run(target, _engine, Finding) or []
    except Exception:  # noqa: BLE001
        return []


SCAFFOLD = '''"""Custom WPSecScan attack script.

Drop in ~/.wpsecscan/attacks/<id>.py and run with:
  wpsecscan --attack <id> https://my-site.com
"""

ATTACK_ID = "example_attack"
ATTACK_NAME = "Example race-condition attack"


def run(target, engine, Finding):
    # `engine` is wpsecscan.turbo_engine — has burst / last_byte_sync / single_packet_h2
    # `Finding` is the standard finding constructor
    results = engine.last_byte_sync(
        target + "/wp-admin/admin-ajax.php?action=my_action",
        n=20,
        method="POST",
        body=b"value=1",
    )
    accepted = sum(1 for r in results if 200 <= (r.get("status") or 0) < 300)
    if accepted > 1:
        return [Finding(
            severity="critical",
            title=f"Race condition observed: {accepted} parallel writes accepted",
            evidence=f"Sent 20 last-byte-synced requests; {accepted} returned 2xx.",
            remediation="Add row-level locking or token de-duplication.",
            url=target,
        )]
    return []
'''


def write_scaffold(path: Path | None = None, *, overwrite: bool = False) -> Path:
    """Drop a starter attack script."""
    p = path or (_attacks_dir() / "example_attack.py")
    if p.exists() and not overwrite:
        raise FileExistsError(p)
    p.write_text(SCAFFOLD, encoding="utf-8")
    return p
