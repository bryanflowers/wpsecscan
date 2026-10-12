"""Version single-source-of-truth: pyproject.toml drives every managed file.

Run `python scripts/bump-version.py --set X.Y.Z` to change the version; this
test fails when any managed file (see RULES in that script) disagrees with
pyproject.toml, or when the imported package reports a different version.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = ROOT / "scripts" / "bump-version.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("bump_version", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_version_drift() -> None:
    drift = _load_script().find_drift(ROOT)
    assert drift == [], "version drift (run scripts/bump-version.py --set X.Y.Z):\n" + "\n".join(drift)


def test_package_version_matches_pyproject() -> None:
    import wpsecscan

    want = _load_script().pyproject_version(ROOT)
    assert wpsecscan.__version__ == want, (
        f"wpsecscan.__version__={wpsecscan.__version__!r} but pyproject.toml={want!r}; "
        "if only the former is stale, the installed metadata is out of date "
        "(re-run `pip install -e .`)"
    )
    assert isinstance(wpsecscan.__version__, str)
