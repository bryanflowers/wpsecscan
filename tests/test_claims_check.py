"""Docs-vs-code claims check (scripts/claims-check.py)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("claims_check", ROOT / "scripts" / "claims-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_computed_values_are_sane():
    facts = _load().compute_facts(ROOT)
    assert facts["checks"] == 295
    assert facts["aggressive"] == 31
    # 65 at v2.8.5; the v2.9.0 `owned` subcommand makes it 66.
    assert facts["subcommands"] in (65, 66)
    assert facts["emit_formats"] == 14
    assert facts["providers"] == 16
    assert facts["helpers"] == 7
    assert facts["provers"] == 5
    assert facts["formats"] == 9
    assert facts["frameworks"] == 12


def test_forbidden_phrase_and_number_detection(tmp_path):
    mod = _load()
    (tmp_path / "README.md").write_text(
        "We ship 12 push providers.\nUse winget install x\n16 push providers ok\n",
        encoding="utf-8",
    )
    facts = {"checks": 295, "aggressive": 31, "passive": 264, "checks_non_auth": 294,
             "subcommands": 66, "emit_formats": 14, "providers": 16, "helpers": 7,
             "provers": 5, "frameworks": 12, "formats": 9, "monitors": 1, "sources": 8}
    counter = [0]
    problems = mod.check(tmp_path, facts=facts, verified=counter)
    assert len(problems) == 2
    assert any("winget install" in p for p in problems)
    assert any("12 push providers" in p for p in problems)
    assert counter[0] == 1


def test_ignore_marker_skips_number_scan_but_not_forbidden_scan(tmp_path):
    mod = _load()
    (tmp_path / "README.md").write_text(
        "We ship 12 push providers. <!-- claims-check: ignore -->\n"
        "brew install x <!-- claims-check: ignore -->\n"
        "We ship 12 push providers.\n",
        encoding="utf-8",
    )
    facts = {"checks": 295, "aggressive": 31, "passive": 264, "checks_non_auth": 294,
             "subcommands": 66, "emit_formats": 14, "providers": 16, "helpers": 7,
             "provers": 5, "frameworks": 12, "formats": 9, "monitors": 1, "sources": 8}
    problems = mod.check(tmp_path, facts=facts, verified=[0])
    assert len(problems) == 2
    assert not any(p.startswith("README.md:1:") for p in problems)
    assert any(p.startswith("README.md:2:") and "brew install" in p for p in problems)
    assert any(p.startswith("README.md:3:") for p in problems)


_FACTS = {"checks": 295, "aggressive": 31, "passive": 264, "checks_non_auth": 294,
          "subcommands": 66, "emit_formats": 14, "providers": 16, "helpers": 7,
          "provers": 5, "frameworks": 12, "formats": 9, "monitors": 1, "sources": 8}


@pytest.mark.parametrize("line", [
    "Supply-chain: SLSA level 3 provenance",
    "supply-chain: slsa l3",
    "WINGET INSTALL wpsecscan",
    "Brew Install wpsecscan",
    "see BUG-bounty.md",
])
def test_forbidden_phrases_are_matched_case_insensitively(tmp_path, line):
    (tmp_path / "README.md").write_text(line + "\n", encoding="utf-8")
    problems = _load().check(tmp_path, facts=_FACTS, verified=[0])
    assert len(problems) == 1, problems
    assert problems[0].startswith("README.md:1: forbidden phrase")


def test_dead_hosts_are_caught_in_extension_manifests_and_ci_templates(tmp_path):
    (tmp_path / "README.md").write_text("fine\n", encoding="utf-8")
    ff = tmp_path / "browser-extension" / "firefox"
    ff.mkdir(parents=True)
    (ff / "manifest.json").write_text(
        '{"gecko": {"id": "x@WPSecScan.DEV"}}\n', encoding="utf-8")
    (tmp_path / "browser-extension" / "popup.js").write_text("// wpsecscan.dev\n", encoding="utf-8")
    ci = tmp_path / "ci"
    ci.mkdir()
    (ci / "gitlab-ci.yml").write_text("script: curl https://wpsecscan.org/x\n", encoding="utf-8")
    (ci / "Jenkinsfile").write_text("// brew install ok here, not a dead host\n", encoding="utf-8")
    problems = _load().check(tmp_path, facts=_FACTS, verified=[0])
    assert sorted(p.split(":")[0] for p in problems) == [
        "browser-extension/firefox/manifest.json", "ci/gitlab-ci.yml"]


def test_repo_extension_manifests_and_ci_have_no_dead_hosts():
    mod = _load()
    for f in mod._dead_host_files(ROOT):
        assert mod._scan_dead_hosts(f, f.relative_to(ROOT).as_posix()) == []


# v2.9.0 W5: hard gate — README/FEATURES/pyproject/docs must agree with the code.
def test_repo_docs_agree_with_code():
    problems = _load().check(ROOT)
    assert not problems, "\n".join(problems)
