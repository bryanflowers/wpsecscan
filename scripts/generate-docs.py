"""Auto-generate per-check markdown docs from check module docstrings.

Usage:
    python scripts/generate-docs.py

Writes one .md per check into ./docs/checks/<check_id>.md plus an
index at docs/checks/README.md. Idempotent — safe to re-run.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wpsecscan.checks import ALL_CHECKS  # noqa: E402


def _tags_for(check_id: str) -> dict:
    p = ROOT / "wpsecscan" / "data" / "check_tags.json"
    try:
        tags = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    return tags.get(check_id, {})


def _compliance_for(check_id: str) -> dict:
    out: dict[str, dict] = {}
    for fname in ("compliance_map.json", "compliance_extra.json", "compliance_v2.json"):
        p = ROOT / "wpsecscan" / "data" / fname
        try:
            d = json.loads(p.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            continue
        if isinstance(d.get(check_id), dict):
            out[fname.replace(".json", "")] = d[check_id]
    return out


def main() -> int:
    out_dir = ROOT / "docs" / "checks"
    out_dir.mkdir(parents=True, exist_ok=True)
    index_lines = ["# WPSecScan check catalogue",
                    "",
                    f"Auto-generated from check docstrings. {len(ALL_CHECKS)} checks total.",
                    "",
                    "| Check ID | Display name | Aggressive | OWASP | MITRE |",
                    "|----------|--------------|-----------|-------|-------|"]

    for cid, display, fn, aggressive in ALL_CHECKS:
        try:
            mod = importlib.import_module(f"wpsecscan.checks.{cid}")
        except ImportError:
            doc = ""
        else:
            doc = (mod.__doc__ or "").strip()
        tags = _tags_for(cid)
        compliance = _compliance_for(cid)

        # Per-check markdown
        page = [f"# {display}", ""]
        page.append(f"**check_id**: `{cid}`")
        page.append(f"**aggressive**: {'yes' if aggressive else 'no'}")
        if tags.get("owasp"):
            page.append(f"**OWASP**: {tags['owasp']} — {tags.get('owasp_label', '')}")
        if tags.get("attack"):
            page.append(f"**MITRE ATT&CK**: {tags['attack']} — {tags.get('attack_label', '')}")
        if tags.get("cwe"):
            page.append(f"**CWE**: {tags['cwe']}")
        if tags.get("d3fend"):
            page.append(f"**D3FEND**: {tags['d3fend']}")
        page.append("")

        if doc:
            page.append("## What it does")
            page.append("")
            page.append(doc)
            page.append("")

        if compliance:
            page.append("## Compliance mapping")
            page.append("")
            for src, entry in compliance.items():
                for k, v in entry.items():
                    page.append(f"- **{src} / {k}**: {v}")
            page.append("")

        page.append("## Run only this check")
        page.append("")
        page.append("```")
        page.append(f"wpsecscan --target https://example.com --only {cid}")
        page.append("```")
        page.append("")

        (out_dir / f"{cid}.md").write_text("\n".join(page), encoding="utf-8")

        index_lines.append(
            f"| [`{cid}`]({cid}.md) | {display} | "
            f"{'⚠' if aggressive else '·'} | "
            f"{tags.get('owasp', '—')} | {tags.get('attack', '—')} |"
        )

    (out_dir / "README.md").write_text("\n".join(index_lines), encoding="utf-8")
    print(f"wrote {len(ALL_CHECKS)} check docs + index to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
