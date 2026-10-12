"""scripts/generate-docs.py — one markdown page per registered check.

The website builds /docs/checks/<id>/ from docs/checks/*.md, so the pages need
YAML front matter, a run command that really exists, and enough check-specific
text to be worth indexing. These tests generate into a tmp dir (no site
checkout needed) and pin those properties.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate-docs.py"
# The website's checks.json supplies each id's category; optional here.
SITE_CHECKS = Path(os.environ.get(
    "WPSECSCAN_SITE_CHECKS_JSON", r"E:\websites\wpsecscan\src\data\checks.json"))

DOCSTRING_MODULES = (
    "debug_leaks", "directory_listing", "exposed_files", "login", "themes",
    "tls_headers", "users", "core_version", "plugins",
)
FRONT_RE = re.compile(r"\A---\n(.*?)\n---\n", re.S)


@pytest.fixture(scope="module")
def sandbox_home(tmp_path_factory):
    """Point HOME at a scratch dir so importing the package never touches ~/.wpsecscan."""
    home = tmp_path_factory.mktemp("home")
    mp = pytest.MonkeyPatch()
    mp.setenv("HOME", str(home))
    mp.setenv("USERPROFILE", str(home))
    mp.setenv("WPSECSCAN_NO_LIVE", "1")
    yield home
    mp.undo()


@pytest.fixture(scope="module")
def gen(sandbox_home):
    spec = importlib.util.spec_from_file_location("generate_docs", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def docs(gen, tmp_path_factory):
    out = tmp_path_factory.mktemp("docs_checks")
    metas = gen.generate(out, SITE_CHECKS if SITE_CHECKS.is_file() else None)
    return out, metas


def _front(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    m = FRONT_RE.match(text)
    assert m, f"{path.name}: no YAML front matter"
    out: dict[str, str] = {}
    for line in m.group(1).splitlines():
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def test_one_page_per_check_plus_readme(docs, gen):
    out, metas = docs
    files = sorted(p.name for p in out.iterdir())
    assert len(metas) == len(gen.ALL_CHECKS) == 295
    assert len(files) == 296
    assert "README.md" in files
    assert {m["id"] + ".md" for m in metas} == set(files) - {"README.md"}


def test_front_matter_id_matches_filename(docs):
    out, _ = docs
    required = {"id", "title", "severity_max", "aggressive", "category", "words"}
    for p in out.glob("*.md"):
        if p.name == "README.md":
            continue
        fm = _front(p)
        assert required <= set(fm), f"{p.name}: missing {required - set(fm)}"
        assert fm["id"] == p.stem
        assert fm["severity_max"] in {"critical", "high", "medium", "low", "info"}
        assert fm["aggressive"] in {"true", "false"}
        assert fm["category"] not in ("", '""')
        assert int(fm["words"]) >= 0


def test_run_command_is_the_real_one(docs, gen):
    out, _ = docs
    for p in out.glob("*.md"):
        text = p.read_text(encoding="utf-8")
        assert "--only" not in text, p.name
        assert "--target" not in text, p.name
    # Passive and aggressive forms.
    waf = (out / "waf.md").read_text(encoding="utf-8")
    assert "wpsecscan only waf https://example.com\n" in waf
    assert gen.run_command("sqli", True) == "wpsecscan only sqli https://example.com --aggressive --owned"
    aggressive_ids = [c[0] for c in gen.ALL_CHECKS if c[3]]
    page = (out / f"{aggressive_ids[0]}.md").read_text(encoding="utf-8")
    assert f"wpsecscan only {aggressive_ids[0]} https://example.com --aggressive --owned" in page


def test_only_subcommand_exists_in_the_cli():
    src = (ROOT / "wpsecscan" / "__main__.py").read_text(encoding="utf-8")
    assert 'elif cmd == "only":' in src
    assert "usage: wpsecscan only CHECK_ID URL" in src


def test_readme_lists_every_check_grouped_by_category(docs):
    out, metas = docs
    readme = (out / "README.md").read_text(encoding="utf-8")
    for m in metas:
        assert f"[`{m['id']}`]({m['id']}.md)" in readme
    assert readme.count("\n## ") >= 8  # category sections


def test_stale_pages_are_deleted(gen, tmp_path):
    (tmp_path / "no_such_check.md").write_text("stale", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("keep", encoding="utf-8")
    gen.generate(tmp_path, None)
    assert not (tmp_path / "no_such_check.md").exists()
    assert (tmp_path / "notes.txt").exists()  # only *.md pages are managed


def test_extraction_is_static_and_finds_findings(gen):
    info = gen._analyse(ROOT / "wpsecscan" / "checks" / "login.py")
    titles = {f["title"] for f in info["findings"]}
    assert "XML-RPC endpoint is enabled" in titles
    assert info["severity_max"] == "medium"
    assert info["requests"] == {"get": 2, "post": 1}
    assert "Login surface appears hardened" in titles


def test_nine_modules_have_docstrings(sandbox_home):
    for name in DOCSTRING_MODULES:
        mod = importlib.import_module(f"wpsecscan.checks.{name}")
        doc = (mod.__doc__ or "").strip()
        assert doc, f"{name} has no module docstring"
        assert 40 <= len(doc.split()) <= 140, f"{name}: {len(doc.split())} words"


def test_word_count_distribution(docs, request):
    out, _ = docs
    words = [int(_front(p)["words"]) for p in out.glob("*.md") if p.name != "README.md"]
    assert len(words) == 295
    ge120 = sum(w >= 120 for w in words)
    ge80 = sum(w >= 80 for w in words)
    lt80 = sum(w < 80 for w in words)
    msg = (f"words distribution over {len(words)} pages: >=120: {ge120}, "
           f">=80: {ge80} (80-119: {ge80 - ge120}), <80: {lt80}, "
           f"min {min(words)}, median {sorted(words)[len(words) // 2]}, max {max(words)}")
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line(msg)
    else:  # pragma: no cover
        print(msg)
    assert ge80 >= 200, msg
