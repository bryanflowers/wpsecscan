"""O46 Markdown export of the trend view.

Walks every snapshot in ~/.wpsecscan/reports/ for a URL, produces a markdown
table + a unicode-spark line graph. Suitable for pasting into a Slack thread
or commit message.
"""
from __future__ import annotations

import json
from pathlib import Path


_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"


def _spark(values: list[int]) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    span = max(1, hi - lo)
    return "".join(_SPARK_BLOCKS[int(((v - lo) / span) * (len(_SPARK_BLOCKS) - 1))] for v in values)


def trend_for_url(url: str) -> list[tuple[str, int]]:
    """Return [(scanned_at, risk_score), ...] sorted ascending by date."""
    from . import history as _h
    safe = _h._safe_filename(url)
    out: list[tuple[str, int]] = []
    reports_dir = Path(_h._home()) / "reports"
    if not reports_dir.exists():
        return out
    for p in sorted(reports_dir.glob(f"*{safe}*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append((d.get("scanned_at", p.stem), int(d.get("risk_score", 0))))
    out.sort()
    return out


def render(url: str) -> str:
    """Build the markdown trend snippet."""
    rows = trend_for_url(url)
    if not rows:
        return f"# Trend for {url}\n\n_No snapshots._\n"
    scores = [r[1] for r in rows]
    lines = [
        f"# Risk-score trend for `{url}`",
        "",
        f"**{len(rows)}** scans · range **{min(scores)}-{max(scores)}** · sparkline: `{_spark(scores)}`",
        "",
        "| Scanned at | Risk score |",
        "|---|---|",
    ]
    for ts, score in rows[-30:]:  # cap at 30 most recent
        lines.append(f"| {ts} | {score}/100 |")
    return "\n".join(lines) + "\n"


def write(url: str, path: Path) -> None:
    path.write_text(render(url), encoding="utf-8")
