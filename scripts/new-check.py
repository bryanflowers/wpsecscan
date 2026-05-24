#!/usr/bin/env python3
"""Interactive check scaffolder — Round-64 #148.

Usage:
    python scripts/new-check.py
    python scripts/new-check.py --id my_check --aggressive
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
CHECKS_DIR = ROOT / "wpsecscan" / "checks"
TEMPLATE_PATH = CHECKS_DIR / "_template.py"

_VALID_ID = re.compile(r"^[a-z][a-z0-9_]{2,40}$")


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{label}{suffix}: ").strip()
    return val or (default or "")


def render(check_id: str, title: str, aggressive: bool, description: str) -> str:
    if not TEMPLATE_PATH.exists():
        return f'''"""{title}

{description}
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("running {check_id}...")
    # TODO: implement the check here
    return findings
'''
    body = TEMPLATE_PATH.read_text(encoding="utf-8")
    body = body.replace("{{CHECK_ID}}", check_id)
    body = body.replace("{{TITLE}}", title)
    body = body.replace("{{DESCRIPTION}}", description)
    return body


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id")
    ap.add_argument("--title")
    ap.add_argument("--aggressive", action="store_true")
    ap.add_argument("--description", default="")
    args = ap.parse_args()

    check_id = args.id or _prompt("Check ID (snake_case, e.g. plugin_xyz_audit)")
    if not _VALID_ID.match(check_id):
        raise SystemExit(f"Invalid check_id {check_id!r}; must match {_VALID_ID.pattern}")
    title = args.title or _prompt("Display title", check_id.replace("_", " ").title())
    description = args.description or _prompt("One-line description")
    aggressive = args.aggressive or (_prompt("Aggressive (active payloads)? y/N", "N").lower().startswith("y"))

    out = CHECKS_DIR / f"{check_id}.py"
    if out.exists():
        raise SystemExit(f"{out} already exists; refusing to overwrite")
    if out.is_symlink():
        out.unlink()
    out.write_text(render(check_id, title, aggressive, description), encoding="utf-8")
    print(f"Wrote {out}")
    print(f"")
    print(f"Next steps:")
    print(f"  1. Edit {out} — fill in the actual check logic")
    print(f"  2. Add to wpsecscan/checks/__init__.py:")
    print(f"       from .{check_id} import check as {check_id}")
    print(f"       ALL_CHECKS.append((\"{check_id}\", \"{title}\", {check_id}, {aggressive}))")
    print(f"  3. Add to wpsecscan/data/check_tags.json")
    print(f"  4. Add tests in tests/test_{check_id}.py")
    print(f"  5. Run: python scripts/lint-checks.py")


if __name__ == "__main__":  # pragma: no cover
    main()
