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
    """Item #65 — Microsoft Teams Adaptive Card 1.5.

    The legacy MessageCard format is officially retired by Microsoft;
    Adaptive Cards 1.5 render natively in modern Teams clients (Outlook
    actionable messages too) with proper severity colour accents,
    columns, and a clickable open-report action when WPSECSCAN_REPORT_URL
    is set (so a CI job can pass a deep link to the artifact).
    """
    d = _summary(report)
    s = d.get("summary", {})
    target = d.get("target", "?")
    risk = int(d.get("risk_score", 0))
    crit = int(s.get("critical", 0))
    high = int(s.get("high", 0))
    if crit:
        color, status_label = "attention", "CRITICAL"
    elif high:
        color, status_label = "warning", "HIGH"
    else:
        color, status_label = "good", "OK"

    def _row(label: str, val: int, accent: str = "default") -> dict:
        return {
            "type": "ColumnSet",
            "columns": [
                {"type": "Column", "width": "auto",
                 "items": [{"type": "TextBlock", "text": label, "wrap": True}]},
                {"type": "Column", "width": "stretch",
                 "items": [{"type": "TextBlock", "text": str(val), "horizontalAlignment": "Right",
                              "weight": "Bolder", "color": accent}]},
            ],
        }

    actions: list[dict] = []
    report_url = os.environ.get("WPSECSCAN_REPORT_URL", "")
    if report_url:
        actions.append({"type": "Action.OpenUrl", "title": "Open full report",
                          "url": report_url})

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.5",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": f"WPSecScan — {target}", "wrap": True},
                    {"type": "TextBlock", "spacing": "None", "isSubtle": True,
                     "text": f"Status: {status_label} · Risk {risk}/100", "color": color},
                    _row("Critical", crit, "attention" if crit else "default"),
                    _row("High",     high, "warning"   if high else "default"),
                    _row("Medium",   int(s.get("medium", 0))),
                    _row("Low",      int(s.get("low", 0))),
                    _row("Info",     int(s.get("info", 0))),
                ],
                **({"actions": actions} if actions else {}),
            },
        }],
    }
    return _post_json(webhook_url, card)


def notify_all(report: Any) -> dict:
    """Dispatch to any webhook URL found in env vars. Returns per-channel result."""
    return {
        "slack":   notify_slack(os.environ.get("WPSECSCAN_SLACK_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_SLACK_WEBHOOK") else None,
        "discord": notify_discord(os.environ.get("WPSECSCAN_DISCORD_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_DISCORD_WEBHOOK") else None,
        "teams":   notify_teams(os.environ.get("WPSECSCAN_TEAMS_WEBHOOK", ""), report) if os.environ.get("WPSECSCAN_TEAMS_WEBHOOK") else None,
    }
