"""v2.9.0 CLI surface — --owned flag, `owned` subcommand, consent wiring for
`only` / `benchmark`, subcommand --help fallback, `kev` feed-unavailable exit.

Offline: sandboxed home, WPSECSCAN_NO_LIVE=1, every network-capable piece mocked.
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from wpsecscan import __main__ as cli
from wpsecscan import consent


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("WPSECSCAN_HOME", str(home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("WPSECSCAN_NO_LIVE", "1")
    monkeypatch.delenv(consent.ENV_OWNED_TARGETS, raising=False)
    monkeypatch.delenv("CI", raising=False)


class _Stop(Exception):
    """Raised by fakes to cut a flow short once the interesting call happened."""


def _capture_args(monkeypatch, argv: list[str]):
    """Run main() with `argv` and return the parsed argparse Namespace."""
    holder: dict = {}

    def _grab(_parser, args):
        holder["args"] = args
        raise _Stop

    monkeypatch.setattr(cli, "_apply_config_and_profile", _grab)
    monkeypatch.setattr(sys, "argv", ["wpsecscan", *argv])
    with pytest.raises(_Stop):
        cli.main()
    return holder["args"]


# (a) owned subcommand --------------------------------------------------------
def test_owned_add_list_remove(capsys):
    cli._dispatch_subcommand("owned", ["add", "https://Example.com:8443/x"])
    capsys.readouterr()
    cli._dispatch_subcommand("owned", ["list"])
    out = capsys.readouterr().out.splitlines()
    assert "example.com" in out
    assert any(line.startswith("file: ") and "owned_targets.json" in line for line in out)
    assert consent.has_consent("https://example.com/")

    cli._dispatch_subcommand("owned", ["remove", "example.com"])
    capsys.readouterr()
    cli._dispatch_subcommand("owned", ["list"])
    out = capsys.readouterr().out.splitlines()
    assert "example.com" not in out
    assert not consent.has_consent("https://example.com/")


def test_owned_bad_usage_exits_64():
    with pytest.raises(SystemExit) as ei:
        cli._dispatch_subcommand("owned", ["add"])
    assert ei.value.code == 64


# (b) parser has --owned ------------------------------------------------------
def test_parser_accepts_owned(monkeypatch):
    args = _capture_args(monkeypatch, ["https://x", "--owned", "--aggressive"])
    assert args.owned is True
    assert args.aggressive is True
    args = _capture_args(monkeypatch, ["https://x", "--aggressive"])
    assert args.owned is False


# (c) _scan_one passes consent ------------------------------------------------
def _scan_one_consent(monkeypatch, argv: list[str]):
    args = _capture_args(monkeypatch, argv + ["--no-console"])
    seen: dict = {}

    async def _fake_scan(target, **kw):
        seen.update(kw)
        raise _Stop

    monkeypatch.setattr(cli, "scan", _fake_scan)
    with pytest.raises(_Stop):
        asyncio.run(cli._scan_one("https://x.invalid", args, cli.Console()))
    return seen


def test_scan_one_passes_consent_true_with_owned(monkeypatch):
    seen = _scan_one_consent(monkeypatch, ["https://x.invalid", "--aggressive", "--owned"])
    assert seen["consent"] is True
    assert seen["aggressive"] is True


def test_scan_one_passes_consent_none_without_owned(monkeypatch, capsys):
    seen = _scan_one_consent(monkeypatch, ["https://x.invalid", "--aggressive"])
    assert seen["consent"] is None
    # non-TTY: one notice line so CI users understand the downgrade
    assert "downgraded to passive" in capsys.readouterr().err


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_tty_prompt_yes_grants_consent(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr(sys, "stdout", _TTY())
    prompts: list[str] = []
    monkeypatch.setattr("builtins.input", lambda p="": prompts.append(p) or "YES")
    args = SimpleNamespace(owned=False, aggressive=True)
    assert cli._resolve_scan_consent("https://x.invalid/", args) is True
    assert prompts and "Type YES" in prompts[0] and "x.invalid" in prompts[0]


def test_tty_prompt_other_answer_keeps_none(monkeypatch):
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr(sys, "stdout", _TTY())
    monkeypatch.setattr("builtins.input", lambda p="": "yes")
    args = SimpleNamespace(owned=False, aggressive=True)
    assert cli._resolve_scan_consent("https://x.invalid/", args) is None


def test_no_prompt_when_not_a_tty(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("must not prompt without a TTY")

    monkeypatch.setattr("builtins.input", _boom)
    args = SimpleNamespace(owned=False, aggressive=True)
    assert cli._resolve_scan_consent("https://x.invalid/", args) is None


def test_no_prompt_when_consent_already_recorded(monkeypatch):
    consent.add_owned("x.invalid")
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr(sys, "stdout", _TTY())

    def _boom(*_a, **_k):
        raise AssertionError("must not prompt when consent is recorded")

    monkeypatch.setattr("builtins.input", _boom)
    args = SimpleNamespace(owned=False, aggressive=True)
    assert cli._resolve_scan_consent("https://x.invalid/", args) is None


# (e) only / benchmark ---------------------------------------------------------
class _FakeClient:
    def __init__(self, *a, **k):
        pass

    async def aclose(self) -> None:
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None


@pytest.fixture
def fake_only(monkeypatch):
    rec: dict = {}

    async def _fn(client, ctx):
        rec["calls"] = rec.get("calls", 0) + 1
        rec["aggressive"] = ctx["aggressive"]
        return []

    # `fake_check` is a passive registry entry, `fake_agg` an aggressive one.
    monkeypatch.setattr("wpsecscan.checks.ALL_CHECKS", [
        ("fake_check", "Fake", _fn, False),
        ("fake_agg", "Fake aggressive", _fn, True),
    ])
    monkeypatch.setattr("wpsecscan.http.Client", _FakeClient)
    return rec


def test_only_downgrades_passive_check_without_consent(fake_only, capsys):
    with pytest.raises(SystemExit):
        cli._cmd_only(["fake_check", "https://x.invalid", "--aggressive"])
    out = capsys.readouterr().out
    assert ("consent_gate: aggressive mode downgraded to passive — "
            "no ownership consent for x.invalid") in out
    assert fake_only["aggressive"] is False


def test_only_keeps_aggressive_with_owned(fake_only, capsys):
    with pytest.raises(SystemExit):
        cli._cmd_only(["fake_check", "https://x.invalid", "--aggressive", "--owned"])
    assert "consent_gate" not in capsys.readouterr().out
    assert fake_only["aggressive"] is True


# (e2) only / refix REFUSE an aggressive registry entry without consent ---------
def test_only_refuses_aggressive_check_without_consent(fake_only, capsys):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_agg", "https://x.invalid"])
    assert ei.value.code == 3
    assert "calls" not in fake_only
    err = capsys.readouterr().err
    assert ("refusing to run aggressive check fake_agg against x.invalid without "
            "ownership consent") in err
    assert "--owned" in err and "WPSECSCAN_OWNED_TARGETS" in err and "owned add x.invalid" in err


def test_only_refuses_aggressive_check_even_with_aggressive_flag(fake_only):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_agg", "https://x.invalid", "--aggressive"])
    assert ei.value.code == 3
    assert "calls" not in fake_only


def test_only_runs_aggressive_check_with_owned_flag(fake_only):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_agg", "https://x.invalid", "--owned"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_only_runs_aggressive_check_with_env_consent(fake_only, monkeypatch):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, "1")
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_agg", "https://x.invalid"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_only_runs_aggressive_check_with_owned_file(fake_only):
    consent.add_owned("x.invalid")
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_agg", "https://x.invalid"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_only_runs_passive_check_without_consent(fake_only):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_only(["fake_check", "https://x.invalid"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_refix_refuses_aggressive_check_without_consent(fake_only, capsys):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_refix(["fake_agg", "https://x.invalid"])
    assert ei.value.code == 3
    assert "calls" not in fake_only
    err = capsys.readouterr().err
    assert ("refusing to run aggressive check fake_agg against x.invalid without "
            "ownership consent") in err


def test_refix_runs_aggressive_check_with_owned_flag(fake_only, capsys):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_refix(["fake_agg", "https://x.invalid", "--owned"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1
    assert "PASS: fake_agg" in capsys.readouterr().out


def test_refix_runs_aggressive_check_with_env_consent(fake_only, monkeypatch):
    monkeypatch.setenv(consent.ENV_OWNED_TARGETS, "1")
    with pytest.raises(SystemExit) as ei:
        cli._cmd_refix(["fake_agg", "https://x.invalid"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_refix_runs_passive_check_without_consent(fake_only):
    with pytest.raises(SystemExit) as ei:
        cli._cmd_refix(["fake_check", "https://x.invalid"])
    assert ei.value.code == 0
    assert fake_only["calls"] == 1


def test_only_and_refix_real_registry_refuse_sqli_without_consent(monkeypatch, capsys):
    # Real registry entry (no fake): sqli is aggressive; the client must never be built.
    from wpsecscan.checks import ALL_CHECKS
    assert [c[3] for c in ALL_CHECKS if c[0] == "sqli"] == [True]

    def _boom(*a, **k):
        raise AssertionError("Client constructed for a refused aggressive check")

    monkeypatch.setattr("wpsecscan.http.Client", _boom)
    for fn in (cli._cmd_only, cli._cmd_refix):
        with pytest.raises(SystemExit) as ei:
            fn(["sqli", "https://x.invalid"])
        assert ei.value.code == 3
    capsys.readouterr()


@pytest.fixture
def fake_bench(monkeypatch):
    rec: dict = {}

    def _select(aggressive=False, authenticated_enabled=False):
        rec["aggressive"] = aggressive
        return []

    monkeypatch.setattr("wpsecscan.checks.select_checks", _select)
    monkeypatch.setattr("wpsecscan.http.Client", _FakeClient)
    return rec


def test_benchmark_downgrades_without_consent(fake_bench, capsys):
    cli._cmd_benchmark(["https://x.invalid", "--aggressive"])
    out = capsys.readouterr().out
    assert ("consent_gate: aggressive mode downgraded to passive — "
            "no ownership consent for x.invalid") in out
    assert fake_bench["aggressive"] is False


def test_benchmark_keeps_aggressive_with_owned(fake_bench, capsys):
    cli._cmd_benchmark(["https://x.invalid", "--aggressive", "--owned"])
    assert "consent_gate" not in capsys.readouterr().out
    assert fake_bench["aggressive"] is True


# kev: feed unavailable -> exit 2 ---------------------------------------------
def test_kev_feed_unavailable_exits_2(monkeypatch, tmp_path, capsys):
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps({"target": "https://x.invalid", "results": []}), encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr("wpsecscan.history.snapshot_history", lambda _u: [snap])
    monkeypatch.setattr("wpsecscan.kev.filter_findings_to_kev", lambda _r: None)
    with pytest.raises(SystemExit) as ei:
        cli._cmd_kev(["https://x.invalid"])
    assert ei.value.code == 2
    assert "[kev] KEV feed unavailable — no filtering applied" in capsys.readouterr().err


# (d) every subcommand answers --help with exit 0 ------------------------------
def test_help_fallback_set_is_known_subcommands():
    assert cli._HELP_FALLBACK_CMDS <= set(cli.SUBCOMMAND_NAMES)
    assert "owned" in cli.SUBCOMMAND_NAMES


@pytest.mark.slow
@pytest.mark.parametrize("name", cli.SUBCOMMAND_NAMES)
def test_every_subcommand_help_exits_zero(name, tmp_path):
    env = dict(os.environ)
    env.update({
        "WPSECSCAN_HOME": str(tmp_path / "h"),
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
        "WPSECSCAN_NO_LIVE": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    proc = subprocess.run(
        [sys.executable, "-m", "wpsecscan", name, "--help"],
        capture_output=True, text=True, timeout=30, env=env, stdin=subprocess.DEVNULL,
        encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 0, (name, proc.returncode, proc.stdout[-300:], proc.stderr[-300:])
