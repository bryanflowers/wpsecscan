"""Microsoft Teams bot adapter for WPSecScan.

Round-64 #168 — accepts a Teams `@mention scan <url>` message and
posts back a card with the summary.
"""
from __future__ import annotations

import os
import asyncio
from typing import Any


WPSECSCAN_DAEMON_URL = os.environ.get("WPSECSCAN_DAEMON_URL", "http://localhost:8080")


def build_adaptive_card(target: str, summary: dict[str, Any]) -> dict:
    """Returns a Teams Adaptive Card v1.5 dict."""
    crit = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    color = "Attention" if crit else "Warning" if high else "Good"
    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "body": [
            {"type": "TextBlock", "text": f"WPSecScan: {target}", "weight": "Bolder", "size": "Medium"},
            {"type": "FactSet", "facts": [
                {"title": "Critical", "value": str(crit)},
                {"title": "High",     "value": str(high)},
                {"title": "Medium",   "value": str(summary.get("medium", 0))},
                {"title": "Low",      "value": str(summary.get("low", 0))},
            ]},
            {"type": "TextBlock", "text": f"Status: {color}", "color": color},
        ],
    }


async def handle_scan_request(target: str) -> dict:
    """Triggers a daemon scan + returns an Adaptive Card."""
    import httpx
    async with httpx.AsyncClient(timeout=300.0) as c:
        r = await c.post(f"{WPSECSCAN_DAEMON_URL}/scans", json={"target": target})
        r.raise_for_status()
        sid = r.json()["scan_id"]
        for _ in range(60):
            await asyncio.sleep(5)
            r2 = await c.get(f"{WPSECSCAN_DAEMON_URL}/scans/{sid}")
            if r2.status_code == 200:
                data = r2.json()
                if data.get("status") == "complete":
                    return build_adaptive_card(target, data.get("summary", {}))
        return build_adaptive_card(target, {})


# Wiring into botbuilder-python TurnContext:
#
#   from botbuilder.core import ActivityHandler, TurnContext
#   class WPSecScanBot(ActivityHandler):
#       async def on_message_activity(self, turn_context: TurnContext):
#           text = (turn_context.activity.text or "").strip()
#           if text.lower().startswith("scan "):
#               target = text.split(maxsplit=1)[1]
#               card = await handle_scan_request(target)
#               await turn_context.send_activity(MessageFactory.attachment(card))
