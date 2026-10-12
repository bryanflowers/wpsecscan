"""v2.9.0 — the composite GitHub Action must only use flags the CLI really has.

The action previously ran `wpsecscan --target URL --json report.json` and a
non-existent `wpsecscan ci-gate` subcommand; the parser has neither. These
tests pin every `--flag` in the action's shell to the real `--help` usage
block, pin the report filename the scanner writes, and exercise the embedded
threshold gate against synthetic reports.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / ".github" / "actions" / "wpsecscan" / "action.yml"

_FLAG_RE = re.compile(r"(?<![\w-])(--[a-z][\w-]*)")


def _action() -> dict:
    return yaml.safe_load(ACTION.read_text(encoding="utf-8"))


def _steps() -> list[dict]:
    return _action()["runs"]["steps"]


def _run_blocks() -> list[str]:
    return [s["run"] for s in _steps() if "run" in s]


def _scan_script() -> str:
    for s in _steps():
        if s.get("id") == "scan":
            return s["run"]
    raise AssertionError("no step with id: scan")


def _cli_flags(tmp_path: Path) -> set[str]:
    home = tmp_path / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
               WPSECSCAN_NO_LIVE="1", PYTHONPATH=str(ROOT))
    out = subprocess.run(
        [sys.executable, "-m", "wpsecscan", "--help"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    # The usage block lists every option; descriptions below it also name
    # flags in prose, so stop at the first section.
    usage = out.stdout.split("positional arguments:", 1)[0]
    return set(_FLAG_RE.findall(usage))


def _flag_tokens(script: str) -> set[str]:
    tokens: set[str] = set()
    for line in script.splitlines():
        if line.lstrip().startswith(("python -m pip", "pip ", "#")):
            continue
        tokens.update(_FLAG_RE.findall(line))
    return tokens


def test_action_yaml_parses_with_composite_steps():
    a = _action()
    assert a["runs"]["using"] == "composite"
    assert "version" in a["inputs"]


def test_every_flag_in_the_action_exists_in_cli_help(tmp_path):
    cli = _cli_flags(tmp_path)
    assert "--out" in cli and "--format" in cli  # sanity: help was parsed
    used: set[str] = set()
    for script in _run_blocks():
        used |= _flag_tokens(script)
    assert used, "no wpsecscan flags found in the action"
    missing = sorted(used - cli)
    assert not missing, f"flags in action.yml absent from `wpsecscan --help`: {missing}"


def test_removed_flags_and_subcommand_are_gone():
    blob = "\n".join(_run_blocks())
    tokens = _flag_tokens(blob)
    assert "--target" not in tokens
    assert "--json" not in tokens
    assert "ci-gate" not in blob


def test_scan_writes_report_json_via_out_and_format():
    script = _scan_script()
    assert "--out report.json" in script
    assert "--format json" in script
    assert "report-path=report.json" in script


def test_target_is_positional():
    # "$INPUT_TARGET" must be an argument of the wpsecscan command itself.
    assert re.search(r'wpsecscan\s+"\$INPUT_TARGET"\s+"\$\{ARGS\[@\]\}"', _scan_script())


def test_install_is_pinned_to_the_version_input():
    install = next(s for s in _steps() if s.get("name") == "Install WPSecScan")
    assert "wpsecscan==${INPUT_VERSION}" in install["run"]
    assert install["env"]["INPUT_VERSION"] == "${{ inputs.version }}"
    default = _action()["inputs"]["version"]["default"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", default)


def test_inputs_are_not_interpolated_into_shell():
    # ${{ inputs.* }} inside `run:` is a script-injection hole; they must
    # travel through env: instead.
    for script in _run_blocks():
        assert "${{" not in script


def test_out_path_resolves_to_report_json_in_cwd(tmp_path, monkeypatch):
    """`--out report.json` => exactly ./report.json (no timestamped name)."""
    from wpsecscan import __main__ as m
    monkeypatch.chdir(tmp_path)
    assert m._outdir("report.json") == tmp_path.resolve()
    assert m._stem("https://example.com", "report.json") == "report"


def _gate_source() -> str:
    gate = next(s for s in _steps() if s.get("name") == "Apply CI gate")
    m = re.search(r"<<'PY'\n(.*?)\nPY\s*$", gate["run"], re.S)
    assert m, "gate heredoc not found"
    return m.group(1)


def _run_gate(tmp_path: Path, summary: dict, max_critical: str, max_high: str) -> int:
    rep = tmp_path / "report.json"
    rep.write_text(json.dumps({"summary": summary}), encoding="utf-8")
    env = dict(os.environ, MAX_CRITICAL=max_critical, MAX_HIGH=max_high)
    return subprocess.run(
        [sys.executable, "-c", _gate_source(), str(rep)],
        env=env, capture_output=True, text=True, timeout=30,
    ).returncode


@pytest.mark.parametrize("summary,max_c,max_h,expected", [
    ({"critical": 0, "high": 5, "medium": 9}, "0", "5", 0),
    ({"critical": 1, "high": 0}, "0", "5", 1),
    ({"critical": 0, "high": 6}, "0", "5", 1),
    ({"info": 3}, "0", "0", 0),
])
def test_gate_reads_summary_from_report_json(tmp_path, summary, max_c, max_h, expected):
    assert _run_gate(tmp_path, summary, max_c, max_h) == expected


# ---- F55 in-toto attestation: real subject digest (not 64 zeros) ----------
def _fixture(**kw):
    base = dict(target="https://example.com", scanned_at="2026-10-12T00:00:00Z",
                risk_score=42, summary={"high": 1, "medium": 1})
    base.update(kw)
    return SimpleNamespace(**base)


def test_intoto_digest_is_real_and_tracks_the_summary():
    from wpsecscan.compliance_v28 import intoto_attestation
    a = intoto_attestation(_fixture())
    b = intoto_attestation(_fixture(summary={"high": 2, "medium": 1}))
    da = a["subject"][0]["digest"]["sha256"]
    db = b["subject"][0]["digest"]["sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", da)
    assert da != "0" * 64
    assert da != db
    assert da == intoto_attestation(_fixture())["subject"][0]["digest"]["sha256"]


def test_intoto_builder_id_default_is_a_url_and_predicate_type_kept():
    from wpsecscan.compliance_v28 import intoto_attestation
    out = intoto_attestation(_fixture())
    assert out["predicate"]["builder"]["id"] == "https://github.com/bryanflowers/wpsecscan"
    assert out["predicateType"] == "https://wpsecscan.com/schema/attest-v1.json"
