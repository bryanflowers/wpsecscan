"""Diff two ScanReport JSON files — highlight new/resolved findings."""
from __future__ import annotations

import json
from pathlib import Path


def _key(finding: dict) -> tuple:
    return (finding.get("severity", ""), finding.get("title", ""), finding.get("url", ""))


def _flatten(report: dict) -> dict[tuple, dict]:
    out: dict[tuple, dict] = {}
    for r in report.get("results", []):
        for f in r.get("findings", []):
            out[_key(f)] = {"check": r.get("check_name", "?"), **f}
    return out


def diff_dicts(old: dict, new: dict) -> dict:
    """Same as `diff()` but takes already-parsed report dicts. Use when
    one side of the comparison is the in-memory current scan instead of
    a file on disk (avoids serializing-then-reparsing JSON)."""
    flat_old = _flatten(old)
    flat_new = _flatten(new)
    new_findings = [f for k, f in flat_new.items() if k not in flat_old]
    resolved = [f for k, f in flat_old.items() if k not in flat_new]
    unchanged = sum(1 for k in flat_new if k in flat_old)
    return {
        "old_target": old.get("target"),
        "new_target": new.get("target"),
        "old_scanned_at": old.get("scanned_at"),
        "new_scanned_at": new.get("scanned_at"),
        "new": sorted(new_findings, key=lambda f: ("critical high medium low info".split().index(f.get("severity", "info")) if f.get("severity") in "critical high medium low info".split() else 99, f.get("title", ""))),
        "resolved": sorted(resolved, key=lambda f: f.get("title", "")),
        "unchanged": unchanged,
    }


def diff(old_path: Path, new_path: Path) -> dict:
    """Return {new: [...], resolved: [...], unchanged: int}."""
    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    flat_old = _flatten(old)
    flat_new = _flatten(new)
    new_findings = [f for k, f in flat_new.items() if k not in flat_old]
    resolved = [f for k, f in flat_old.items() if k not in flat_new]
    unchanged = sum(1 for k in flat_new if k in flat_old)
    return {
        "old_target": old.get("target"),
        "new_target": new.get("target"),
        "old_scanned_at": old.get("scanned_at"),
        "new_scanned_at": new.get("scanned_at"),
        "new": sorted(new_findings, key=lambda f: ("critical high medium low info".split().index(f.get("severity", "info")) if f.get("severity") in "critical high medium low info".split() else 99, f.get("title", ""))),
        "resolved": sorted(resolved, key=lambda f: f.get("title", "")),
        "unchanged": unchanged,
    }


def render_text(d: dict) -> str:
    lines = [
        "# WPSecScan diff",
        f"  old: {d['old_target']}  @ {d['old_scanned_at']}",
        f"  new: {d['new_target']}  @ {d['new_scanned_at']}",
        "",
        f"New findings: {len(d['new'])}",
        f"Resolved:     {len(d['resolved'])}",
        f"Unchanged:    {d['unchanged']}",
        "",
    ]
    if d["new"]:
        lines.append("## NEW")
        for f in d["new"]:
            lines.append(f"  [{f.get('severity','?').upper():>8}]  {f.get('check','?'):<30}  {f.get('title','')[:80]}")
    if d["resolved"]:
        lines.append("\n## RESOLVED")
        for f in d["resolved"]:
            lines.append(f"  [{f.get('severity','?').upper():>8}]  {f.get('check','?'):<30}  {f.get('title','')[:80]}")
    return "\n".join(lines)
