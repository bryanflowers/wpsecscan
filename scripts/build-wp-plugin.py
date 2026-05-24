"""Zip the WP companion plugin into a wp.org-ready installable archive.

Usage:
    python scripts/build-wp-plugin.py

Writes dist/wpsecscan-companion.zip suitable for "Plugins → Upload Plugin"
in WP admin.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "wp-plugin" / "wpsecscan-companion"
OUT = ROOT / "dist" / "wpsecscan-companion.zip"


def main() -> int:
    if not SRC.is_dir():
        print(f"missing {SRC}", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    # Always start fresh
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(SRC.rglob("*")):
            if f.is_file() and ".DS_Store" not in f.name:
                arc = f.relative_to(SRC.parent)  # keeps top-level dir name
                zf.write(f, arc)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
