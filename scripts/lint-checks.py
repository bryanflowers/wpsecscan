#!/usr/bin/env python3
"""Lint all checks for hygiene — Round-64 #149.

Flags:
  - check modules without a module-level docstring
  - check modules whose `check()` function isn't async
  - check modules importing requests (sync) instead of using Client
  - check modules not registered in ALL_CHECKS
  - check IDs not present in data/check_tags.json
  - bare `except:` clauses
  - `datetime.utcnow()` (deprecated)
  - `subprocess.call(..., shell=True)`
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CHECKS_DIR = ROOT / "wpsecscan" / "checks"
INIT = CHECKS_DIR / "__init__.py"
TAGS = ROOT / "wpsecscan" / "data" / "check_tags.json"


def lint_file(p: Path) -> list[str]:
    issues = []
    try:
        src = p.read_text(encoding="utf-8")
    except OSError as e:
        return [f"read error: {e}"]
    if "import requests" in src:
        issues.append("imports requests (use wpsecscan.http.Client instead)")
    if "datetime.utcnow()" in src:
        issues.append("uses deprecated datetime.utcnow() — use datetime.now(tz=timezone.utc)")
    if re.search(r"subprocess\.\w+\([^)]*shell\s*=\s*True", src):
        issues.append("subprocess call with shell=True — pass list args instead")
    if re.search(r"^\s*except\s*:\s*$", src, re.MULTILINE):
        issues.append("bare `except:` — catch specific exceptions or `except Exception:`")
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [f"syntax error: {e}"]
    if not (ast.get_docstring(tree) or "").strip():
        issues.append("missing module docstring")
    found_check_fn = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "check":
            found_check_fn = True
            break
        if isinstance(node, ast.FunctionDef) and node.name == "check":
            issues.append("check() must be `async def`, not `def`")
            found_check_fn = True
    if not found_check_fn:
        issues.append("missing `async def check(client, ctx)` function")
    return issues


def main() -> int:
    if not CHECKS_DIR.is_dir():
        print(f"Not a directory: {CHECKS_DIR}", file=sys.stderr)
        return 1

    init_src = INIT.read_text(encoding="utf-8") if INIT.exists() else ""
    registered_ids: set[str] = set()
    for m in re.finditer(r'\(\s*"([a-z][a-z0-9_]+)"\s*,\s*"[^"]+"', init_src):
        registered_ids.add(m.group(1))

    tags_src = TAGS.read_text(encoding="utf-8") if TAGS.exists() else "{}"
    import json
    try:
        tag_keys = set(json.loads(tags_src).keys())
    except ValueError:
        tag_keys = set()

    total = 0
    failed = 0
    for p in sorted(CHECKS_DIR.glob("*.py")):
        if p.name.startswith("_"):
            continue
        total += 1
        cid = p.stem
        issues = lint_file(p)
        if cid not in registered_ids:
            issues.append("not registered in checks/__init__.py:ALL_CHECKS")
        if cid not in tag_keys:
            issues.append("missing entry in data/check_tags.json")
        if issues:
            failed += 1
            print(f"{p.relative_to(ROOT)}:")
            for i in issues:
                print(f"  - {i}")
    print(f"\n{total} check modules scanned, {failed} with issues.")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
