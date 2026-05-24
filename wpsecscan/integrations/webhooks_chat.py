"""Round-60 #3 — Slack / Discord / Microsoft Teams webhook alerters.

Pure stdlib HTTP. Each function takes a webhook URL and a report and
posts a summary. Returns True/False — never raises.

Honors WPSECSCAN_NO_NETWORK (test env / air-gapped mode).
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.error import HTTPError, URLError
from typing import Any


def _post_json(url: str, body: dict, *, timeout: float = 10.0,
                headers: dict | None = None) -> bool:
    if not url or not url.startswith(("http://", "https://")):
        return False
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return False
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                  "User-Agent": "WPSecScan/webhooks_chat", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 300
    except (HTTPError, URLError, OSError, ValueError):
        return False


def _summary(report: Any) -> dict:
    """Tolerant — accepts dict or ScanReport-like."""
    if hasattr(report, "to_dict"):
        return report.to_dict()
    return report if isinstance(report, dict) else {}


def notify_slack(webhook_url: str, report: Any) -> bool:
    d = _summary(report)
    s = d.get("summary", {})
    target = d.get("target", "?")
    risk = d.get("risk_score", 0)
    crit = int(s.get("critical", 0))
    high = int(s.get("high", 0))
    color = "danger" if crit else ("warning" if high else "good")
    payload = {
        "text": f"WPSecScan scan complete — {target}",
        "attachments": [{
            "color": color,
            "title": f"Risk {risk}/100",
            "fields": [
                {"title": "Critical", "value": str(crit), "short": True},
                {"title": "High", "value": str(high), "short": True},
                {"title": "Medium", "value": str(s.get("medium", 0)), "short": True},
                {"title": "Low", "value": str(s.get("low", 0)), "short": True},
            ],
        }],
    }
    return _post_json(webhook_url, payload)


def notify_discord(webhook_url: str, report: Any) -> bool:
    d = _summary(report)
    s = d.get("summary", {})
    target = d.get("target", "?")
    risk = d.get("risk_score", 0)
    color = 0xff0000 if s.get("critical", 0) else (0xff9900 if s.get("high", 0) else 0x00cc00)
    payload = {
        "username": "WPSecScan",
        "embeds": [{
            "title": f"Scan complete — {target}",
            "color": color,
            "fields": [
                {"name": "Risk", "value": f"{risk}/100", "inline": True},
                {"name": "Critical", "value": str(s.get("critical", 0)), "inline": True},
                {"name": "High", "value": str(s.get("high", 0)), "inline": True},
                {"name": "Medium", "value": str(s.get("medium", 0)), "inline": True},
                {"name": "Low", "value": str(s.get("low", 0)), "inline": True},
            ],
        }],
    }
    return _post_json(webhook_url, payload)


def notify_teams(webhook_url: str, report: Any) -> bool:
    d = _summary(report)
    s = d.get("summary", {})
    target = d.get("target", "?")
    risk = d.get("risk_score", 0)
    crit = int(s.get("critical", 0))
    color = "FF0000" if crit else ("FF9900" if s.get("high", 0) else "00CC00")
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": f"WPSecScan — {target}",
        "title": f"WPSecScan scan complete — {target}",
        "sections": [{
            "facts": [
                {"name": "Risk", "value": f"{risk}/100"},
                {"name": "Critical", "value": str(crit)},
                {"name": "High", "value": str(s.get("high", 0))},
                {"name": "Medium", "value": str(s.get("medium", 0))},
                {"name": "Low", "value": str(s.get("low", 0))},
            ],
        }],
    }
    return _post_json(webhook_url, payload)


def notify_all(report: Any) -> dict:
    """Dispatch to any webhook URL found in env vars. Returns per-channel result."""
    return {
        "slack":   notify_slack(os.environ.get("WPSECSCAN_SLACK_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_SLACK_WEBHOOK") else None,
        "discord": notify_discord(os.environ.get("WPSECSCAN_DISCORD_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_DISCORD_WEBHOOK") else None,
        "teams":   notify_teams(os.environ.get("WPSECSCAN_TEAMS_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_TEAMS_WEBHOOK") else None,
    }
