"""Screen-reader-friendly CLI output.

Round-64 #100 — `--screen-reader` flag strips all ANSI escapes, box-
drawing characters, and emoji, and emits one finding per line in a
predictable "severity: title — url" format.
"""
from __future__ import annotations

import re


# Strip CSI/SGR escapes
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# Strip common decorative chars
_BOX_CHARS = "".join(chr(c) for c in range(0x2500, 0x257F + 1))
_EMOJI_RANGES = (
    (0x1F300, 0x1FAFF),  # rough emoji block
    (0x2600,  0x27BF),
)


def strip_decorations(s: str) -> str:
    s = _ANSI_RE.sub("", s)
    # Strip box-drawing chars
    s = "".join(c for c in s if c not in _BOX_CHARS)
    # Strip emoji
    def _is_emoji(c: str) -> bool:
        cp = ord(c)
        return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)
    s = "".join(c for c in s if not _is_emoji(c))
    # Collapse repeated whitespace
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def render_findings(findings: list) -> str:
    """One line per finding: 'SEVERITY: TITLE - URL'."""
    if not findings:
        return "OK: No findings."
    lines = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        line = f"{d.get('severity', 'info').upper()}: {d.get('title', '')} — {d.get('url', '')}"
        lines.append(strip_decorations(line))
    lines.append(f"TOTAL: {len(findings)} findings.")
    return "\n".join(lines)
