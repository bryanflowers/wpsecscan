"""scripts/export-site-data.py — the website's numbers are computed from code.

The exporter writes <site>/src/data/checks.json and release.json. These tests
run it into a tmp dir (no site checkout needed) and pin the sane values.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "export-site-data.py"


@pytest.fixture(scope="module")
def exporter():
    spec = importlib.util.spec_from_file_location("export_site_data", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def site(tmp_path, exporter):
    assert exporter.main(["--site-dir", str(tmp_path)]) == 0
    return tmp_path


def _load(site: Path, name: str) -> dict:
    return json.loads((site / "src" / "data" / name).read_text(encoding="utf-8"))


def test_release_counts(site):
    rel = _load(site, "release.json")
    assert rel["checks"] == 294
    assert rel["checks_total"] == 295
    assert rel["aggressive"] == 31
    assert rel["categories"] == 11
    assert rel["formats"] == 9 and len(rel["format_list"]) == 9
    assert rel["emit_formats"] == 14
    assert rel["push_providers"] == 16
    assert rel["ai_helpers"] == 7
    assert rel["proof_helpers"] == 5
    assert rel["compliance_frameworks"] == 12 and len(rel["compliance_list"]) == 12
    assert rel["feed_sources_configured"] == 8
    assert rel["threat_intel_providers"] == 10
    assert rel["exe_size_mb"] == 31
    assert rel["license"] == "AGPL-3.0-or-later"


def test_subcommands_match_code(site):
    import wpsecscan.__main__ as cli

    rel = _load(site, "release.json")
    assert rel["subcommands"] == len(cli.SUBCOMMAND_HELP)
    assert rel["subcommands"] >= 65  # 65 at v2.8.5; v2.9.0 only adds


def test_release_identity_and_urls(site):
    rel = _load(site, "release.json")
    assert rel["tag"] == "v" + rel["version"]
    assert rel["python_min"] == "3.10"
    assert rel["release_url"].endswith("/releases/tag/" + rel["tag"])
    base = "/releases/download/" + rel["tag"] + "/"
    assert set(rel["assets"]) == {"exe", "gui_exe", "wheel", "sdist", "sha256sums", "sbom"}
    assert all(base in url for url in rel["assets"].values())
    assert rel["pypi_url"].startswith("https://pypi.org/project/wpsecscan")
    assert len(rel["date"]) == 10


def test_checks_json_shape(site):
    chk = _load(site, "checks.json")
    cats = chk["categories"]
    assert chk["_total"] == 294
    assert len(cats) == 11
    assert sum(c["count"] for c in cats) == 294
    assert all(c["count"] == len(c["checks"]) for c in cats)
    ids = [ck["id"] for c in cats for ck in c["checks"]]
    assert len(ids) == len(set(ids)) == 294
    assert "authenticated" not in ids
    assert chk["_aggressive_count"] == sum(
        1 for c in cats for ck in c["checks"] if ck["aggressive"])
    assert set(chk["_generated_from"]) == {"version", "commit"}
    row = cats[0]["checks"][0]
    assert set(row) == {"id", "name", "aggressive", "owasp", "owasp_label", "attack",
                        "attack_label", "cwe", "d3fend", "pci_dss", "nist_800_53", "iso_27001"}


def test_check_mode(site, exporter, capsys):
    assert exporter.main(["--site-dir", str(site), "--check"]) == 0
    # A commit change alone is not drift ...
    p = site / "src" / "data" / "checks.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["_generated_from"]["commit"] = "0" * 40
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    assert exporter.main(["--site-dir", str(site), "--check"]) == 0
    # ... but a changed count is.
    rel_p = site / "src" / "data" / "release.json"
    rel = json.loads(rel_p.read_text(encoding="utf-8"))
    rel["checks"] = 1
    rel_p.write_text(json.dumps(rel, indent=2) + "\n", encoding="utf-8")
    assert exporter.main(["--site-dir", str(site), "--check"]) == 1
    assert "release.json" in capsys.readouterr().err


def test_check_mode_missing_files(tmp_path, exporter):
    assert exporter.main(["--site-dir", str(tmp_path), "--check"]) == 1
