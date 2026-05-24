#!/usr/bin/env python3
"""Generate CONTRIBUTORS.md from git shortlog.

Round-64 #129 — parses git log and emits a Markdown leaderboard.

Usage:
    python community/scripts/gen_contributors.py [--since DATE] [--out PATH]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


def _git_shortlog(since: str | None = None) -> list[tuple[int, str]]:
    """Returns [(commit_count, 'Name <email>'), ...]."""
    cmd = ["git", "shortlog", "-sne", "HEAD"]
    if since:
        cmd.extend(["--since", since])
    out = subprocess.check_output(cmd, encoding="utf-8")
    rows = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\s+(.+)$", line)
        if m:
            rows.append((int(m.group(1)), m.group(2)))
    rows.sort(reverse=True)
    return rows


def _name_to_handle(name_email: str) -> str:
    # If email is `<user>@users.noreply.github.com`, that's the GH handle
    m = re.search(r"<([^@]+)@users\.noreply\.github\.com>", name_email)
    if m:
        return f"[@{m.group(1)}](https://github.com/{m.group(1)})"
    # Else just show the name
    return name_email.split("<")[0].strip()


def render(rows: list[tuple[int, str]], header: str) -> str:
    lines = [f"# {header}", "", "Thank you to everyone who has contributed.", "",
             "| Rank | Contributor | Commits |", "|------|-------------|---------|"]
    for i, (count, who) in enumerate(rows[:50], 1):
        lines.append(f"| {i} | {_name_to_handle(who)} | {count} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default=None, help="git --since arg, e.g. '90.days.ago'")
    ap.add_argument("--out", default="CONTRIBUTORS.md")
    ap.add_argument("--header", default="WPSecScan Contributors")
    args = ap.parse_args()
    try:
        rows = _git_shortlog(since=args.since)
    except subprocess.CalledProcessError as e:
        print(f"git shortlog failed: {e}", file=sys.stderr)
        sys.exit(1)
    if not rows:
        print("No contributors found in shortlog", file=sys.stderr)
        sys.exit(0)
    out = Path(args.out)
    if out.is_symlink():
        out.unlink()
    out.write_text(render(rows, args.header), encoding="utf-8")
    print(f"Wrote {len(rows)} contributors to {out}")


if __name__ == "__main__":  # pragma: no cover
    main()
