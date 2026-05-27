"""Shared utilities — extracted from duplicated patterns surfaced by
the post-v2.5.0 audit (commit 3, Wave 2A).

Three helpers, each replacing a copy-pasted pattern at 5+ call sites:

  load_home_json(filename, default)
      Read JSON from ~/.wpsecscan/{filename}. Returns `default` on
      missing file, malformed JSON, or I/O error. Logs a one-line
      warning to stderr on corruption so the operator notices.

  parse_kv_args(args, *, flags, bools)
      Parse a list of CLI tokens into a {flag-name: value} dict.
      `flags` is a list of accepted `--flag` strings that take one
      value argument; `bools` is the list of standalone switches.
      Unknown tokens are returned as a separate `extras` list so the
      caller can decide whether to error or accept them.

  custom_check_dirs()
      Return the canonical list of directories the scanner searches
      for user-supplied check modules. Single source of truth — three
      previous independent definitions are now imports.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def home_dir() -> Path:
    """Return the WPSECSCAN_HOME path, defaulting to ~/.wpsecscan."""
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def load_home_json(filename: str, default: Any) -> Any:
    """Read JSON from ~/.wpsecscan/{filename}; fall back to `default`.

    Missing file → silent default. Malformed JSON → stderr warning +
    default (so an operator notices a corruption rather than silently
    losing state). Other I/O errors → silent default.
    """
    p = home_dir() / filename
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"warning: ~/.wpsecscan/{filename} is malformed JSON ({e}); "
               f"falling back to default. Re-create or fix the file.",
               file=sys.stderr)
        return default
    except OSError:
        return default


def parse_kv_args(
    args: list[str],
    *,
    flags: list[str],
    bools: list[str] | None = None,
) -> tuple[dict[str, str], list[bool], list[str]]:
    """Parse `--flag VALUE` pairs + `--bool-switch` standalones.

    Returns (kv_dict, bool_dict, extras). `flags` and `bools` accept
    the leading `--`. Unknown tokens collect in `extras` in order.

    Example:
        kv, bools, extras = parse_kv_args(
            ["--name", "x", "--draft", "leftover"],
            flags=["--name", "--out"],
            bools=["--draft"],
        )
        # kv == {"name": "x"}, bools == {"draft": True}, extras == ["leftover"]
    """
    flag_set = set(flags)
    bool_set = set(bools or [])
    kv: dict[str, str] = {}
    bool_kv: dict[str, bool] = {}
    extras: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in flag_set:
            if i + 1 < len(args):
                kv[a.lstrip("-").replace("-", "_")] = args[i + 1]
                i += 2
                continue
            # Flag with missing value — treat as boolean True for
            # forward-compat (caller can detect absence by missing key).
            i += 1
            continue
        if a in bool_set:
            bool_kv[a.lstrip("-").replace("-", "_")] = True
            i += 1
            continue
        extras.append(a)
        i += 1
    return kv, bool_kv, extras  # type: ignore[return-value]


def custom_check_dirs() -> list[Path]:
    """Return the canonical list of dirs the scanner loads user checks
    from. Order matters — earlier entries take precedence on duplicate
    CHECK_ID (the legacy `plugins/` location still wins for back-compat
    with users who installed there pre-v2.5.0)."""
    home = home_dir()
    return [
        home / "plugins",                 # legacy (pre-v2.5.0)
        home / "checks",                  # canonical (post-v2.5.0)
        home / "marketplace" / "checks",  # marketplace downloads
    ]
