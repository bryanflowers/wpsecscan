"""Slack slash-command handler for `/wpsecscan scan <url>`.

Round-64 #167 — Bolt-for-Python style handler. Stub — needs
SLACK_BOT_TOKEN + SLACK_SIGNING_SECRET to actually run.
"""
from __future__ import annotations

import os
import asyncio
from typing import Any


WPSECSCAN_DAEMON_URL = os.environ.get("WPSECSCAN_DAEMON_URL", "http://localhost:8080")


async def trigger_scan(target: str) -> dict[str, Any]:
    import httpx
    async with httpx.AsyncClient(timeout=300.0) as c:
        r = await c.post(f"{WPSECSCAN_DAEMON_URL}/scans", json={"target": target})
        r.raise_for_status()
        sid = r.json()["scan_id"]
        for _ in range(60):
            r2 = await c.get(f"{WPSECSCAN_DAEMON_URL}/scans/{sid}")
            r2.raise_for_status()
            d = r2.json()
            if d.get("status") == "complete":
                return d
            await asyncio.sleep(5)
        return {"error": "timeout"}


def format_slack_message(target: str, scan_result: dict[str, Any]) -> dict:
    summary = scan_result.get("summary", {})
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    color = "danger" if crit else "warning" if high else "#fbc02d" if medium else "good"
    return {
        "response_type": "in_channel",
        "attachments": [{
            "color": color,
            "title": f"WPSecScan results: {target}",
            "fields": [
                {"title": "Critical", "value": str(crit), "short": True},
                {"title": "High",     "value": str(high), "short": True},
                {"title": "Medium",   "value": str(medium), "short": True},
                {"title": "Risk score", "value": str(scan_result.get("risk_score", "n/a")), "short": True},
            ],
        }],
    }


def build_bolt_app() -> Any:
    """Returns a slack_bolt.App. Caller does .start() with their socket-mode token."""
    try:
        from slack_bolt.async_app import AsyncApp  # type: ignore
    except ImportError as e:
        raise ImportError("pip install slack_bolt required for the Slack bot") from e

    app = AsyncApp(
        token=os.environ["SLACK_BOT_TOKEN"],
        signing_secret=os.environ["SLACK_SIGNING_SECRET"],
    )

    @app.command("/wpsecscan")
    async def handle(ack, respond, command):
        await ack()
        parts = (command.get("text") or "").split()
        if len(parts) < 2 or parts[0] != "scan":
            await respond("Usage: `/wpsecscan scan <url>`")
            return
        target = parts[1]
        await respond(f"Starting scan of {target}...")
        result = await trigger_scan(target)
        await respond(format_slack_message(target, result))

    return app
