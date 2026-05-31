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


# ---------------------------------------------------------------------------
# Q7 — schema-versioned state files
# ---------------------------------------------------------------------------

CURRENT_SCHEMA_VERSION = 1


def load_versioned_json(filename: str, default: Any,
                          *, expected_version: int = CURRENT_SCHEMA_VERSION) -> Any:
    """Read a {"_version": N, "data": ...} wrapper from ~/.wpsecscan/{filename}.

    Backward-compat: unwrapped legacy data (no `_version` key) is accepted
    silently and treated as version 1. A version higher than expected logs
    a stderr warning so a future v2.6 → v2.5 downgrade is visible.
    """
    raw = load_home_json(filename, None)
    if raw is None:
        return default
    if isinstance(raw, dict) and "_version" in raw and "data" in raw:
        v = raw.get("_version")
        if isinstance(v, int) and v > expected_version:
            print(f"warning: ~/.wpsecscan/{filename} is schema v{v}; "
                   f"this build expects v{expected_version}. Older fields "
                   f"may be ignored; consider upgrading wpsecscan.",
                   file=sys.stderr)
        return raw["data"]
    # Legacy / unwrapped — treat as v1.
    return raw


def save_versioned_json(filename: str, data: Any,
                          *, version: int = CURRENT_SCHEMA_VERSION) -> None:
    """Atomically write {"_version": N, "data": ...} to ~/.wpsecscan/{filename}.

    Atomic via os.replace; the partial file is at `{filename}.tmp.{pid}`
    during the write so a crash mid-write leaves the previous version intact.
    """
    p = home_dir() / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"_version": version, "data": data}
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def validate_out_path(path_str: str, *, allowed_root: Path | None = None) -> Path:
    """v2.8.1 B41 — validate a user-supplied --out path. Rejects:
      - Empty / whitespace
      - Symlinks resolving outside `allowed_root` (when provided)
      - Paths that don't fit on the filesystem (eg. write-permission
        denied at the parent dir level).

    Returns a resolved Path on success. Raises ValueError on failure
    with an actionable message. Caller passes the result to the
    reporter's `write(report, path)`.

    Pre-v2.8.1 every `--out FILE` arg was passed verbatim to a reporter
    that called `path.write_text(...)`; an operator passing
    `--out ../../etc/crontab` got an unchecked write attempt (limited
    by OS permissions only). Now: realpath check + writability check
    + optional prefix check.
    """
    s = (path_str or "").strip()
    if not s:
        raise ValueError("--out must not be empty")
    try:
        p = Path(s).expanduser().resolve(strict=False)
    except (OSError, ValueError, RuntimeError) as e:
        raise ValueError(f"--out: cannot resolve path {s!r}: {e}") from e
    if allowed_root is not None:
        try:
            root = Path(allowed_root).expanduser().resolve(strict=False)
        except (OSError, ValueError, RuntimeError):
            root = Path(allowed_root)
        try:
            p.relative_to(root)
        except ValueError as e:
            raise ValueError(
                f"--out: {p} is outside allowed root {root} "
                f"(symlink escape or path-traversal attempt)"
            ) from e
    # Probe write-ability by ensuring the parent dir exists.
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as e:
        raise ValueError(f"--out: parent dir not writable: {e}") from e
    return p


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
