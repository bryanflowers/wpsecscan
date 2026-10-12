#!/usr/bin/env python3
"""Claims check — compare the numbers and phrases in the docs against the code.

Computes the countable facts from CODE (registry size, subcommands, emit
formats, push providers, AI helpers, proof helpers, compliance frameworks,
`--format` choices, CVE sources), then scans README.md, FEATURES.md,
pyproject.toml (description) and docs/*.md for

  * number-claims next to the words checks / subcommands / formats /
    providers / helpers / frameworks / verifiers / monitors / sources that
    disagree with the computed values, and
  * phrases that must not appear (channels that do not exist, retired
    claims, dead hosts).

Usage:  python scripts/claims-check.py [REPO_ROOT]
Exit status 1 on any mismatch. Stdlib only, Python 3.10+.
"""
from __future__ import annotations

import ast
import contextlib
import inspect
import json
import os
import re
import sys
import tempfile
from pathlib import Path

# Phrases that must not appear in the scanned files.
FORBIDDEN = (
    r"SLSA L3",
    r"SLSA Level 3",
    r"intoto",
    r"10 PoC",
    r"10 always-on",
    r"8 free sources",
    r"every check is tagged with .*CWE",
    r"winget install",
    r"brew install",
    r"snap install",
    r"choco install",
    r"yay -S",
    r"ghcr\.io",
    r"docker pull",
    r"wpsecscan scan ",
    r"--verify-exploits",
    r"BUG-BOUNTY",
    r"wpsecscan\.dev",
    r"wpsecscan\.org",
    r"\b1066\b",
    r"\b1097\b",
)

# A line containing this marker is skipped by the number scan (not by FORBIDDEN),
# e.g. `<!-- claims-check: ignore -->` after a historical figure.
IGNORE_MARKER = "claims-check: ignore"

# keyword (regex) -> key into the computed-facts dict
_KEYWORDS = (
    (r"checks?", "checks"),
    (r"sub-?commands?", "subcommands"),
    (r"(?:report |output |emit )?formats?", "formats"),
    (r"(?:push )?providers?", "providers"),
    (r"helpers?", "helpers"),
    (r"frameworks?", "frameworks"),
    (r"(?:verifiers?|provers?)", "provers"),
    (r"monitors?", "monitors"),
    (r"sources?", "sources"),
)

# Numbers that are legitimate for each keyword (several code-derived counts can
# honestly sit next to the same word, e.g. 295 checks / 294 non-auth / 31 aggressive).
_ALLOWED_KEYS = {
    "checks": ("checks", "checks_non_auth", "aggressive", "passive"),
    "subcommands": ("subcommands",),
    "formats": ("formats", "emit_formats"),
    "providers": ("providers",),
    "helpers": ("helpers",),
    "frameworks": ("frameworks",),
    "provers": ("provers",),
    "monitors": ("monitors",),
    "sources": ("sources",),
}

_NUM_CLAIM = re.compile(
    r"(?<![\w.])(\d[\d,]*)(\+?)(?:-|\s+)"
    r"(?:[A-Za-z][\w/.\-]*\s+){0,2}?"
    r"(" + "|".join(k for k, _ in _KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Historical files: number-claims there describe past releases, so only the
# forbidden-phrase scan applies.
_HISTORICAL = {"whats-new.md", "CHANGELOG.md"}


@contextlib.contextmanager
def _sandbox_home():
    """Point HOME-ish env vars at a throwaway dir while importing the package."""
    keys = ("HOME", "USERPROFILE", "WPSECSCAN_HOME", "WPSECSCAN_NO_LIVE")
    saved = {k: os.environ.get(k) for k in keys}
    with tempfile.TemporaryDirectory(prefix="wpsec-claims-") as tmp:
        os.environ["HOME"] = tmp
        os.environ["USERPROFILE"] = tmp
        os.environ["WPSECSCAN_HOME"] = tmp
        os.environ["WPSECSCAN_NO_LIVE"] = "1"
        try:
            yield
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def _format_choices(main_py: Path) -> list[str]:
    """`--format` values, read from the add_argument(...) call's help text."""
    tree = ast.parse(main_py.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and node.args):
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and first.value == "--format"):
            continue
        for kw in node.keywords:
            if kw.arg == "help" and isinstance(kw.value, ast.Constant):
                m = re.search(r"Supported:\s*([\w,\-]+)", kw.value.value)
                if m:
                    return [x for x in m.group(1).split(",") if x]
    return []


def _compliance_keys(root: Path) -> set[str]:
    keys: set[str] = set()
    for name in ("compliance_map.json", "compliance_v2.json", "compliance_extra.json"):
        data = json.loads((root / "wpsecscan" / "data" / name).read_text(encoding="utf-8"))
        for cid, entry in data.items():
            if cid.startswith("_") or not isinstance(entry, dict):
                continue
            keys.update(k for k in entry if not k.startswith("_"))
    return keys


def compute_facts(root: Path) -> dict:
    """Countable facts, derived from the code under `root`."""
    root = Path(root)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    with _sandbox_home():
        from wpsecscan import __main__ as m
        from wpsecscan import prove
        from wpsecscan.checks import ALL_CHECKS

        push_src = inspect.getsource(m._cmd_push)
        block = push_src.split("dispatch: dict[str, tuple[str, str]] = {", 1)[1].split("\n    }", 1)[0]
        providers = re.findall(r'^\s+"([\w-]+)":\s*\(', block, re.MULTILINE)
        ai_subs = set(re.findall(r'\bsub == "([\w-]+)"', inspect.getsource(m._cmd_ai)))
        formats = _format_choices(root / "wpsecscan" / "__main__.py")
        aggressive = sum(1 for c in ALL_CHECKS if c[3])
        feed_src = (root / "scripts" / "aggregate-cve-feed.py").read_text(encoding="utf-8")
        sources_block = feed_src.split("SOURCES = {", 1)[1].split("}", 1)[0]
        sources = re.findall(r'^\s+"(\w+)":', sources_block, re.MULTILINE)
        facts = {
            "checks": len(ALL_CHECKS),
            "aggressive": aggressive,
            "passive": len(ALL_CHECKS) - aggressive,
            "checks_non_auth": sum(1 for c in ALL_CHECKS if c[0] != "authenticated"),
            "subcommands": len(m.SUBCOMMAND_HELP),
            "emit_formats": len(m._EMIT_DISPATCH),
            "providers": len(providers),
            "helpers": len(ai_subs),
            "provers": len(prove.PROVERS),
            "frameworks": len(_compliance_keys(root)),
            "formats": len(formats),
            "monitors": 1,  # continuous_monitor.py is the single monitor module
            "sources": len(sources),
        }
    return facts


def _scan_files(root: Path) -> list[Path]:
    files = [root / "README.md", root / "FEATURES.md", root / "pyproject.toml"]
    docs = root / "docs"
    if docs.is_dir():
        files.extend(sorted(docs.glob("*.md")))
    return [f for f in files if f.is_file()]


def _scan_text(path: Path, rel: str, facts: dict, verified: list[int]) -> list[str]:
    out: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "pyproject.toml":
        # Only the description string is a public claim.
        m = re.search(r'^description\s*=\s*"(.*)"\s*$', text, re.MULTILINE)
        text = m.group(1) if m else ""
    historical = path.name in _HISTORICAL
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat in FORBIDDEN:
            if re.search(pat, line):
                out.append(f"{rel}:{lineno}: forbidden phrase /{pat}/: {line.strip()[:120]}")
        if historical or IGNORE_MARKER in line:
            continue
        for m in _NUM_CLAIM.finditer(line):
            # Incremental / partial counts ("26 new checks", "7 other sources")
            # are not claims about the totals.
            if re.search(r"\b(?:new|other|more|extra|additional|consecutive)\b", m.group(0), re.IGNORECASE):
                continue
            num = int(m.group(1).replace(",", ""))
            plus = bool(m.group(2))
            word = m.group(3).lower()
            fkey = next(k for pat, k in _KEYWORDS if re.fullmatch(pat, word, re.IGNORECASE))
            allowed = [facts[k] for k in _ALLOWED_KEYS[fkey]]
            ok = num in allowed or (plus and num <= max(allowed))
            if ok:
                verified[0] += 1
            else:
                out.append(
                    f"{rel}:{lineno}: claims {m.group(0).strip()!r}; code says "
                    f"{fkey}={'/'.join(str(a) for a in allowed)}"
                )
    return out


def check(root, facts: dict | None = None, verified: list[int] | None = None) -> list[str]:
    """Return a list of mismatch strings (empty means every claim agrees)."""
    root = Path(root)
    facts = facts or compute_facts(root)
    counter = verified if verified is not None else [0]
    problems: list[str] = []
    for f in _scan_files(root):
        rel = f.relative_to(root).as_posix()
        problems.extend(_scan_text(f, rel, facts, counter))
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent
    facts = compute_facts(root)
    print("computed: " + ", ".join(f"{k}={v}" for k, v in facts.items()))
    verified = [0]
    problems = check(root, facts, verified)
    if problems:
        for p in problems:
            print("MISMATCH " + p)
        print(f"FAIL: {len(problems)} mismatch(es), {verified[0]} claims verified")
        return 1
    print(f"OK: {verified[0]} claims verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
