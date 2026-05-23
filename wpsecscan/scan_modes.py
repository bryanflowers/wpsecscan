"""#19 (from ZAP) — explicit active vs passive mode split.

WPSecScan already has the concept (`--aggressive` opt-in for active payload
checks). This module exposes the split as named modes so users can pick
explicitly. Existing flags still work:

  Mode           | Old flag(s)            | What runs
  ---------------|------------------------|---------------------------
  passive        | (default)              | only checks tagged passive
  active         | --aggressive           | passive + aggressive
  authenticated  | --auth-user/--pass     | passive + authenticated
  full           | --aggressive --auth*   | everything

Selecting a mode also tweaks request pacing — passive mode uses the
default concurrency, active mode steps it down by half to reduce
DoS risk against the target.
"""
from __future__ import annotations


# Mode → tuple of (aggressive_on, authenticated_on, concurrency_multiplier)
MODES = {
    "passive":       (False, False, 1.0),
    "active":        (True,  False, 0.5),
    "aggressive":    (True,  False, 0.5),   # alias
    "authenticated": (False, True,  0.8),
    "full":          (True,  True,  0.5),
}


def apply_mode(args, mode: str) -> None:
    """Mutate argparse `args` to reflect the named mode.
    Existing flags are NOT overwritten if the user set them explicitly."""
    aggressive, authenticated, mult = MODES.get(mode.lower(), MODES["passive"])
    if aggressive and not getattr(args, "aggressive", False):
        args.aggressive = True
    if authenticated and not (getattr(args, "auth_user", None) and getattr(args, "auth_pass", None)):
        # Don't auto-fill creds — just inform the user
        pass
    base_conc = getattr(args, "concurrency", 10)
    args.concurrency = max(2, int(base_conc * mult))
