"""v2.8.1 U15 — structured CLI error reporting.

Replaces ad-hoc `print(...) ; sys.exit(2)` with a typed dataclass that
the GUI / LSP / mobile-API can ingest. Keep optional — existing callers
still work, but new error sites should `raise CliError(...)` and let
the top-level handler print + exit cleanly.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CliError(Exception):
    """A user-facing CLI error with a machine-readable code + structured detail."""
    code: str                      # short slug, e.g. "missing-arg" / "bad-token"
    message: str                   # one-line human-readable message
    exit_code: int = 2             # POSIX sysexits.h value, default EX_USAGE
    hint: str | None = None        # optional remediation hint shown after the error
    detail: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:  # noqa: D401
        return self.message


def handle_cli_error(err: CliError, *, json_mode: bool = False) -> int:
    """Print `err` to stderr and return its exit_code. Top-level catch-all."""
    if json_mode:
        import json as _json
        out = {
            "code": err.code,
            "message": err.message,
            "hint": err.hint,
            "detail": err.detail,
            "exit_code": err.exit_code,
        }
        print(_json.dumps(out), file=sys.stderr)
    else:
        print(f"error: {err.message}", file=sys.stderr)
        if err.hint:
            print(f"hint: {err.hint}", file=sys.stderr)
    return err.exit_code
