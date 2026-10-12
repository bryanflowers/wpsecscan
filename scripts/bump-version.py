#!/usr/bin/env python3
"""Single-source version management for WPSecScan.

The source of truth is ``pyproject.toml`` ``[project] version``. Every other
file that embeds the program version is listed in ``RULES`` below.

    python scripts/bump-version.py --check        # exit 1 + list file:line drift
    python scripts/bump-version.py --set 2.9.0    # rewrite pyproject + managed files

``--set`` prints one ``CHANGED <path>`` line per file it modified (paths are
relative to the repo root, forward slashes) so callers such as release.ps1 can
stage exactly those files.

Files are read and written as bytes so existing line endings (CRLF in this
repo) and encodings are preserved. Stdlib only; Python 3.10+.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable, NamedTuple

VERSION_RE = r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?"
SET_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$")


def _full(v: str) -> str:
    return v


def _core(v: str) -> str:
    """Numeric ``a.b.c`` core (MSI / Windows version resources are numeric only)."""
    return v.split("-", 1)[0]


def _tuple(v: str) -> str:
    return ", ".join(_core(v).split("."))


class Rule(NamedTuple):
    path: str
    # Regex with three groups: (prefix)(version-text)(suffix).
    pattern: str
    fmt: Callable[[str], str]
    min_matches: int = 1
    max_matches: int = 0  # 0 = all matches are managed; N = only the first N


RULES: tuple[Rule, ...] = (
    Rule("wpsecscan/__init__.py",
         rf'(?m)^(_FALLBACK_VERSION = ")({VERSION_RE})(")', _full),
    Rule("version_info.txt",
         r"(filevers=\()(\d+, \d+, \d+)(, 0\))", _tuple),
    Rule("version_info.txt",
         r"(prodvers=\()(\d+, \d+, \d+)(, 0\))", _tuple),
    Rule("version_info.txt",
         rf"('FileVersion', ')({VERSION_RE})(')", _core),
    Rule("version_info.txt",
         rf"('ProductVersion', ')({VERSION_RE})(')", _core),
    Rule("installer/wpsecscan-setup.nsi",
         rf'(?m)^(!define APP_VERSION[ \t]+")({VERSION_RE})(")', _full),
    Rule("installer/wpsecscan.wxs",
         rf"(wpsecscan-)({VERSION_RE})(\.msi)", _full),
    Rule("installer/wpsecscan.wxs",
         rf'(<Package\b[^>]*?\bVersion=")({VERSION_RE})(")', _core),
    Rule("installer/README.md",
         rf"(wpsecscan-setup-)({VERSION_RE})(\.exe)", _full),
    Rule("installer/README.md",
         rf"(wpsecscan-)({VERSION_RE})(\.msi)", _full, min_matches=2),
    Rule("openapi/wpsecscan-api.yaml",
         rf'(?m)^(  version: ")({VERSION_RE})(")', _full, max_matches=1),
    Rule("sdks/go/wpsecscan/client.go",
         rf'(?m)^(const Version = ")({VERSION_RE})(")', _full),
    Rule("sdks/python/wpsecscan_client/__init__.py",
         rf'(?m)^(__version__ = ")({VERSION_RE})(")', _full),
    Rule("docker-compose.yml",
         rf"(?m)^([ \t]+image: wpsecscan:)({VERSION_RE})()", _full),
    Rule("Dockerfile",
         rf'(?m)^(LABEL org\.opencontainers\.image\.version=")({VERSION_RE})(")', _full),
    # The composite GitHub Action pins the PyPI version it installs; the
    # default must follow each release or CI users silently stay behind.
    Rule(".github/actions/wpsecscan/action.yml",
         rf'(?m)^(    default: ")({VERSION_RE})(")', _full, max_matches=1),
)

PYPROJECT = "pyproject.toml"


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _write(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _project_version_match(text: str) -> re.Match[str] | None:
    """First ``version = "..."`` line inside the ``[project]`` table."""
    sec = re.search(r"(?m)^\[project\][ \t]*\r?$", text)
    if not sec:
        return None
    nxt = re.search(r"(?m)^\[", text[sec.end():])
    end = sec.end() + nxt.start() if nxt else len(text)
    m = re.compile(rf'(?m)^(version[ \t]*=[ \t]*")({VERSION_RE})(")').search(
        text, sec.end(), end)
    return m


def pyproject_version(root: Path) -> str:
    text = _read(root / PYPROJECT)
    m = _project_version_match(text)
    if not m:
        raise SystemExit(f"{PYPROJECT}: no [project] version line found")
    return m.group(2)


def _matches(rule: Rule, text: str) -> list[re.Match[str]]:
    found = list(re.finditer(rule.pattern, text))
    if rule.max_matches:
        found = found[: rule.max_matches]
    return found


def find_drift(root: str | Path) -> list[str]:
    """Return one ``path:line: ...`` string per drifted/missing managed value."""
    root = Path(root)
    want = pyproject_version(root)
    drift: list[str] = []
    for rule in RULES:
        path = root / rule.path
        if not path.is_file():
            drift.append(f"{rule.path}: file missing")
            continue
        text = _read(path)
        found = _matches(rule, text)
        if len(found) < rule.min_matches:
            drift.append(
                f"{rule.path}: expected >={rule.min_matches} match(es) of "
                f"/{rule.pattern}/, found {len(found)}")
            continue
        expect = rule.fmt(want)
        for m in found:
            if m.group(2) != expect:
                drift.append(
                    f"{rule.path}:{_line_of(text, m.start(2))}: "
                    f"found {m.group(2)}, expected {expect}")
    return drift


def set_version(root: str | Path, new: str) -> list[str]:
    """Rewrite pyproject + managed files. Returns repo-relative paths changed."""
    root = Path(root)
    if not SET_RE.match(new):
        raise SystemExit(f"version must look like 1.2.3 or 1.2.3-rc1; got {new!r}")
    changed: list[str] = []

    pp = root / PYPROJECT
    text = _read(pp)
    m = _project_version_match(text)
    if not m:
        raise SystemExit(f"{PYPROJECT}: no [project] version line found")
    if m.group(2) != new:
        _write(pp, text[: m.start(2)] + new + text[m.end(2):])
        changed.append(PYPROJECT)

    by_path: dict[str, list[Rule]] = {}
    for rule in RULES:
        by_path.setdefault(rule.path, []).append(rule)
    for rel, rules in by_path.items():
        path = root / rel
        if not path.is_file():
            raise SystemExit(f"{rel}: file missing")
        orig = text = _read(path)
        for rule in rules:
            found = _matches(rule, text)
            if len(found) < rule.min_matches:
                raise SystemExit(
                    f"{rel}: expected >={rule.min_matches} match(es) of "
                    f"/{rule.pattern}/, found {len(found)}")
            value = rule.fmt(new)
            # Replace right-to-left so earlier offsets stay valid.
            for m in reversed(found):
                text = text[: m.start(2)] + value + text[m.end(2):]
        if text != orig:
            _write(path, text)
            changed.append(rel)
    return changed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true",
                   help="exit 1 and list every drifted file:line")
    g.add_argument("--set", metavar="X.Y.Z", dest="new",
                   help="set pyproject.toml and every managed file to X.Y.Z")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent),
                    help="repo root (default: parent of scripts/)")
    args = ap.parse_args(argv)
    root = Path(args.root)

    if args.check:
        drift = find_drift(root)
        if drift:
            print(f"version drift vs pyproject.toml ({pyproject_version(root)}):")
            for line in drift:
                print(f"  {line}")
            return 1
        print("OK")
        return 0

    changed = set_version(root, args.new)
    for rel in changed:
        print(f"CHANGED {rel}")
    if not changed:
        print(f"no changes; everything already at {args.new}")
    drift = find_drift(root)
    if drift:
        print("post-write drift (bug in RULES):")
        for line in drift:
            print(f"  {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
