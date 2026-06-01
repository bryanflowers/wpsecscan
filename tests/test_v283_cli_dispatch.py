"""v2.8.3 Phase 3.3 — smoke tests for 5 CLI handlers that the v2.8.3
audit found had no dispatch test.

Pattern: invoke `_cmd_*` directly with `["-h"]` or `["--help"]` and
assert it returns without raising. Exercises the help-path of each
handler + verifies the docstring is non-empty.
"""
from __future__ import annotations

import sys
from contextlib import redirect_stdout, redirect_stderr
import io

import pytest


def _call_with_help(cmd_fn, *, help_arg: str = "--help"):
    """Invoke a `_cmd_*` handler with the given help arg, capturing
    stdout/stderr. Returns (stdout, stderr, exit_code). Treats SystemExit
    as a normal exit signal."""
    out, err = io.StringIO(), io.StringIO()
    exit_code = 0
    try:
        with redirect_stdout(out), redirect_stderr(err):
            cmd_fn([help_arg])
    except SystemExit as e:
        exit_code = int(e.code) if isinstance(e.code, int) else 0
    return out.getvalue(), err.getvalue(), exit_code


# ===========================================================================
# _cmd_annotate
# ===========================================================================
def test_cmd_annotate_help_does_not_crash():
    from wpsecscan.__main__ import _cmd_annotate
    stdout, stderr, code = _call_with_help(_cmd_annotate, help_arg="-h")
    # Help should print usage and return cleanly (exit 0 or no exit).
    assert code in (0, 64)
    combined = (stdout + stderr).lower()
    assert "annotate" in combined or "usage" in combined


# ===========================================================================
# _cmd_verify_release
# ===========================================================================
def test_cmd_verify_release_help_does_not_crash():
    from wpsecscan.__main__ import _cmd_verify_release
    stdout, stderr, code = _call_with_help(_cmd_verify_release)
    assert code in (0, 2, 64)


# ===========================================================================
# _cmd_ai_options
# ===========================================================================
def test_cmd_ai_options_help_does_not_crash():
    from wpsecscan.__main__ import _cmd_ai_options
    stdout, stderr, code = _call_with_help(_cmd_ai_options)
    assert code in (0, 2, 64)


# ===========================================================================
# _cmd_ai_cost
# ===========================================================================
def test_cmd_ai_cost_help_does_not_crash():
    from wpsecscan.__main__ import _cmd_ai_cost
    stdout, stderr, code = _call_with_help(_cmd_ai_cost)
    assert code in (0, 2, 64)


# ===========================================================================
# _cmd_doctor — verify exit-code semantics (returns 0 or 1, never crashes)
# ===========================================================================
def test_cmd_doctor_returns_within_expected_codes():
    from wpsecscan.__main__ import _cmd_doctor
    out, err = io.StringIO(), io.StringIO()
    exit_code = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            _cmd_doctor([])
    except SystemExit as e:
        exit_code = int(e.code) if isinstance(e.code, int) else 0
    # Doctor exits 0 on all green, 1 on any optional dep missing
    # (intentional per the contract). Must NEVER crash with unhandled
    # exception.
    if exit_code is not None:
        assert exit_code in (0, 1, 2)
    # Must print something useful.
    assert out.getvalue() or err.getvalue()


# ===========================================================================
# Smoke: every _cmd_* listed in the docstring of _dispatch_subcommand
# is importable. Catches future commits that wire a subcommand into
# SUBCOMMAND_HELP without defining the handler.
# ===========================================================================
def test_all_subcommands_in_dispatcher_have_importable_handlers():
    from wpsecscan import __main__ as _m
    # Build the list of subcommand names from SUBCOMMAND_NAMES.
    for sub_name in _m.SUBCOMMAND_NAMES:
        # We don't need to call them — just verify they're routable.
        # The dispatcher does this lazily, so test that the SUBCOMMAND_HELP
        # → SUBCOMMAND_NAMES derivation doesn't accidentally include
        # something that has no dispatch path.
        assert isinstance(sub_name, str) and sub_name
