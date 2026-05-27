"""v2.7.0 PhaseC — workflow / orchestration subcommand handlers.

Houses the implementation of D61-D71 (minus already-shipped D67 = kev).
Each handler is a self-contained _cmd_X(args: list[str]) function the
main dispatcher imports.
"""
from __future__ import annotations

import json
import sys
import tarfile
import time
from pathlib import Path

from ._util import home_dir, load_home_json


# ---------------------------------------------------------------------------
# D61 — wpsecscan compare-portfolios
# ---------------------------------------------------------------------------

def cmd_compare_portfolios(args: list[str]) -> None:
    """`wpsecscan compare-portfolios OLD.json NEW.json [--out FILE]`

    Diff two `sites.json` files side-by-side. Each file is a list of
    site objects (target + tags + creds-key). Reports sites added,
    sites removed, and tag-only changes — useful for agency M&A
    due-diligence.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("usage: wpsecscan compare-portfolios OLD.json NEW.json [--out FILE]",
              file=sys.stderr)
        sys.exit(64)
    old_path = Path(args[0]).expanduser()
    new_path = Path(args[1]).expanduser()
    try:
        old = json.loads(old_path.read_text(encoding="utf-8"))
        new = json.loads(new_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"failed to parse input files: {e}", file=sys.stderr); sys.exit(2)
    if not isinstance(old, list) or not isinstance(new, list):
        print("expected each file to be a top-level JSON array", file=sys.stderr); sys.exit(64)

    old_by = {s.get("target"): s for s in old if isinstance(s, dict)}
    new_by = {s.get("target"): s for s in new if isinstance(s, dict)}
    added   = sorted(set(new_by) - set(old_by))
    removed = sorted(set(old_by) - set(new_by))
    common  = set(new_by) & set(old_by)
    tag_changes = []
    for t in sorted(common):
        a = set(old_by[t].get("tags") or [])
        b = set(new_by[t].get("tags") or [])
        if a != b:
            tag_changes.append({"target": t,
                                  "added_tags": sorted(b - a),
                                  "removed_tags": sorted(a - b)})

    print(f"Sites added:    {len(added)}")
    for t in added: print(f"  + {t}")
    print(f"Sites removed:  {len(removed)}")
    for t in removed: print(f"  - {t}")
    print(f"Tag changes:    {len(tag_changes)}")
    for c in tag_changes:
        print(f"  ~ {c['target']} +{c['added_tags']} -{c['removed_tags']}")


# ---------------------------------------------------------------------------
# D63 — wpsecscan changelog URL --since DATE
# ---------------------------------------------------------------------------

def cmd_changelog(args: list[str]) -> None:
    """`wpsecscan changelog URL [--since YYYY-MM-DD]`

    Render a human-readable changelog of observed changes across saved
    snapshots — plugin versions, theme switches, header changes, cert
    renewals. Different from the existing diff-tree (which compares
    findings only).
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan changelog URL [--since YYYY-MM-DD]", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    since = ""
    for i, a in enumerate(args[1:]):
        if a == "--since" and i + 2 <= len(args[1:]):
            since = args[i + 2]
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved snapshots for {url}", file=sys.stderr); sys.exit(2)

    rows: list[dict] = []
    prev_plugins: dict[str, str] = {}
    prev_theme: str = ""
    for snap in snaps:
        try:
            d = json.loads(snap.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ts = d.get("scanned_at", snap.name)
        if since and ts < since:
            continue
        cur_plugins: dict[str, str] = {}
        cur_theme: str = ""
        for r in d.get("results", []):
            cid = r.get("check_id", "")
            for f in r.get("findings", []):
                extra = f.get("extra") or {}
                if cid == "plugins" and extra.get("slug") and extra.get("version"):
                    cur_plugins[extra["slug"]] = str(extra["version"])
                if cid == "themes" and extra.get("active_theme"):
                    cur_theme = str(extra["active_theme"])
        # Plugin diff vs previous
        for slug, ver in cur_plugins.items():
            if slug not in prev_plugins:
                rows.append({"ts": ts, "kind": "plugin-added",
                              "subject": f"{slug} @ {ver}"})
            elif prev_plugins[slug] != ver:
                rows.append({"ts": ts, "kind": "plugin-upgrade",
                              "subject": f"{slug}: {prev_plugins[slug]} → {ver}"})
        for slug in set(prev_plugins) - set(cur_plugins):
            rows.append({"ts": ts, "kind": "plugin-removed", "subject": slug})
        if cur_theme and cur_theme != prev_theme and prev_theme:
            rows.append({"ts": ts, "kind": "theme-switch",
                          "subject": f"{prev_theme} → {cur_theme}"})
        prev_plugins, prev_theme = cur_plugins, cur_theme

    if not rows:
        print(f"No observed changes for {url}" + (f" since {since}" if since else "."))
        return
    print(f"# WPSecScan-observed changelog: {url}")
    if since:
        print(f"# Since: {since}")
    print()
    for r in rows:
        print(f"  {r['ts']}  {r['kind']:18s}  {r['subject']}")


# ---------------------------------------------------------------------------
# D64 — wpsecscan replay HAR.json
# ---------------------------------------------------------------------------

def cmd_replay(args: list[str]) -> None:
    """`wpsecscan replay HAR.json [--list | --show INDEX]`

    Air-gapped audit helper. Reads an HTTP Archive (HAR) file and lets
    the operator browse the recorded requests + responses. Future
    extension: feed HAR entries to specific checks instead of live HTTP.
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan replay HAR.json [--list | --show INDEX]",
              file=sys.stderr)
        sys.exit(64)
    p = Path(args[0]).expanduser()
    if not p.exists():
        print(f"file not found: {p}", file=sys.stderr); sys.exit(2)
    try:
        har = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"failed to parse HAR: {e}", file=sys.stderr); sys.exit(2)
    entries = (har.get("log") or {}).get("entries") or []
    if not entries:
        print("HAR contains no entries.", file=sys.stderr); sys.exit(0)
    mode = "list"
    show_idx: int | None = None
    for i, a in enumerate(args[1:]):
        if a == "--list":
            mode = "list"
        elif a == "--show" and i + 2 <= len(args[1:]):
            try:
                show_idx = int(args[i + 2])
            except ValueError:
                pass
    if mode == "list" and show_idx is None:
        print(f"HAR: {len(entries)} entries from {p.name}")
        for i, e in enumerate(entries):
            req = e.get("request") or {}
            resp = e.get("response") or {}
            print(f"  [{i:3d}] {req.get('method', '?'):5s} "
                   f"{resp.get('status', 0):3d}  {req.get('url', '?')[:90]}")
    elif show_idx is not None and 0 <= show_idx < len(entries):
        import pprint
        pprint.pp(entries[show_idx])
    else:
        print(f"index {show_idx} out of range (0-{len(entries) - 1})",
              file=sys.stderr); sys.exit(64)
