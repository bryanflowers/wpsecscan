"""Attack timeline builder from companion-plugin audit log + WAF logs.

Round-64 #175 — given the companion plugin's audit log JSON + an
optional WAF log (Cloudflare/Wordfence/Sucuri format), merge events
chronologically into a single timeline + flag suspicious clusters.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class TimelineEvent:
    timestamp: str      # ISO-8601
    source: str         # "wp-audit" / "waf" / "wpsecscan-finding"
    actor: str          # IP, user, or "system"
    action: str
    target: str         # URL or resource
    severity: str = "info"
    details: dict[str, Any] = None  # type: ignore[assignment]


def parse_wp_audit_log(path: Path) -> list[TimelineEvent]:
    out: list[TimelineEvent] = []
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            out.append(TimelineEvent(
                timestamp=e.get("ts", ""),
                source="wp-audit",
                actor=str(e.get("actor", "?")),
                action=str(e.get("action", "?")),
                target=str(e.get("target", "?")),
                severity=str(e.get("severity", "info")),
                details=e.get("details") or {},
            ))
    except OSError:
        pass
    return out


def parse_cf_log_jsonl(path: Path) -> list[TimelineEvent]:
    """Cloudflare Logpush JSON Lines."""
    out: list[TimelineEvent] = []
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            ts_raw = e.get("EdgeStartTimestamp") or e.get("ts")
            if ts_raw and isinstance(ts_raw, int):
                ts = datetime.fromtimestamp(ts_raw / 1e9, tz=timezone.utc).isoformat()
            else:
                ts = str(ts_raw) if ts_raw else ""
            out.append(TimelineEvent(
                timestamp=ts,
                source="waf",
                actor=str(e.get("ClientIP", "?")),
                action=str(e.get("ClientRequestMethod", "?")) + " " + str(e.get("ClientRequestPath", "?")),
                target=str(e.get("ClientRequestHost", "?")),
                severity="medium" if int(e.get("EdgeResponseStatus", 0)) >= 400 else "info",
                details={k: e.get(k) for k in ("WAFAction", "WAFRuleID", "EdgeResponseStatus")},
            ))
    except OSError:
        pass
    return out


def merge_findings(findings: list[dict], scanned_at: str) -> list[TimelineEvent]:
    out = []
    for f in findings:
        out.append(TimelineEvent(
            timestamp=scanned_at,
            source="wpsecscan-finding",
            actor="wpsecscan",
            action=f.get("title", "?"),
            target=f.get("url", "?"),
            severity=f.get("severity", "info"),
            details=f.get("extra") or {},
        ))
    return out


def build_timeline(events: list[TimelineEvent]) -> list[TimelineEvent]:
    """Sort + dedupe."""
    def _key(e: TimelineEvent):
        return e.timestamp or ""
    return sorted(events, key=_key)


def flag_suspicious_clusters(events: list[TimelineEvent], *, window_seconds: int = 30, min_failed_requests: int = 10) -> list[dict]:
    """Naive scan: same actor, > N 4xx/5xx WAF events in `window_seconds` seconds.

    Returns list of {"actor", "start_ts", "end_ts", "count"}.
    """
    by_actor: dict[str, list[TimelineEvent]] = {}
    for e in events:
        if e.source != "waf":
            continue
        sev = (e.severity or "").lower()
        if sev not in ("medium", "high", "critical"):
            continue
        by_actor.setdefault(e.actor, []).append(e)

    clusters: list[dict] = []
    for actor, evs in by_actor.items():
        evs.sort(key=lambda x: x.timestamp)
        i = 0
        n = len(evs)
        while i < n:
            window = [evs[i]]
            j = i + 1
            try:
                start_dt = datetime.fromisoformat(evs[i].timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                i += 1
                continue
            while j < n:
                try:
                    cur_dt = datetime.fromisoformat(evs[j].timestamp.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    break
                if (cur_dt - start_dt).total_seconds() <= window_seconds:
                    window.append(evs[j])
                    j += 1
                else:
                    break
            if len(window) >= min_failed_requests:
                clusters.append({
                    "actor":    actor,
                    "start_ts": window[0].timestamp,
                    "end_ts":   window[-1].timestamp,
                    "count":    len(window),
                })
            i = j
    return clusters


def render_timeline_html(events: list[TimelineEvent], clusters: list[dict]) -> str:
    """Simple HTML report."""
    rows = []
    for e in events:
        rows.append(
            f"<tr>"
            f"<td>{e.timestamp}</td><td>{e.source}</td><td>{e.actor}</td>"
            f"<td>{e.action}</td><td>{e.target}</td><td>{e.severity}</td></tr>"
        )
    cluster_rows = []
    for c in clusters:
        cluster_rows.append(
            f"<tr><td>{c['actor']}</td><td>{c['start_ts']}</td>"
            f"<td>{c['end_ts']}</td><td>{c['count']}</td></tr>"
        )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>WPSecScan Forensics Timeline</title>
<style>
body {{ font-family: sans-serif; padding: 1em; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; font-size: 12px; }}
th {{ background: #f7f7f7; }}
</style></head><body>
<h1>Forensics Timeline</h1>
<h2>Suspicious clusters</h2>
<table>
<thead><tr><th>Actor</th><th>Start</th><th>End</th><th>Count</th></tr></thead>
<tbody>{''.join(cluster_rows) or '<tr><td colspan=4>None detected</td></tr>'}</tbody>
</table>
<h2>Full timeline ({len(events)} events)</h2>
<table>
<thead><tr><th>Timestamp</th><th>Source</th><th>Actor</th><th>Action</th><th>Target</th><th>Sev</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</body></html>
"""
