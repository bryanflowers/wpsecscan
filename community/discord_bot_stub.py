"""WPSecScan Discord bot — `/wpsecscan-scan <url>` slash command stub.

Round-64 #125 — minimal discord.py bot that fires a daemon scan and
posts the summary to the channel. Stub — needs DISCORD_TOKEN +
WPSECSCAN_DAEMON_URL env vars to actually run.
"""
from __future__ import annotations

import os
import asyncio

try:
    import discord  # type: ignore
    from discord import app_commands  # type: ignore
    _DISCORD_AVAILABLE = True
except ImportError:
    discord = None  # type: ignore
    _DISCORD_AVAILABLE = False


WPSECSCAN_DAEMON_URL = os.environ.get("WPSECSCAN_DAEMON_URL", "http://localhost:8080")


async def _trigger_scan(target: str) -> dict:
    """Calls the daemon REST API. Returns summary dict."""
    import httpx
    async with httpx.AsyncClient(timeout=300.0) as c:
        r = await c.post(f"{WPSECSCAN_DAEMON_URL}/scans", json={"target": target})
        r.raise_for_status()
        scan_id = r.json()["scan_id"]
        # Poll for completion
        for _ in range(60):
            r2 = await c.get(f"{WPSECSCAN_DAEMON_URL}/scans/{scan_id}")
            r2.raise_for_status()
            data = r2.json()
            if data.get("status") == "complete":
                return data.get("summary", {})
            await asyncio.sleep(5)
        return {}


def build_bot() -> "discord.Client":
    if not _DISCORD_AVAILABLE:
        raise ImportError("pip install discord.py required for the Discord bot")

    intents = discord.Intents.default()
    client = discord.Client(intents=intents)
    tree = app_commands.CommandTree(client)

    @tree.command(name="wpsecscan-scan", description="Run a WPSecScan scan against a URL")
    async def scan_cmd(interaction: discord.Interaction, url: str):  # noqa: D401
        await interaction.response.defer(thinking=True)
        try:
            summary = await _trigger_scan(url)
        except Exception as e:  # noqa: BLE001
            await interaction.followup.send(f"Scan failed: {e}")
            return
        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        emoji = "🔴" if crit else "🟠" if high else "🟡" if med else "🟢"
        await interaction.followup.send(
            f"{emoji} **{url}**\n"
            f"  • Critical: {crit}\n"
            f"  • High:     {high}\n"
            f"  • Medium:   {med}\n"
            f"  • Low:      {summary.get('low', 0)}"
        )

    @client.event
    async def on_ready():
        await tree.sync()

    return client


def main() -> None:
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit("Set DISCORD_TOKEN env var")
    client = build_bot()
    client.run(token)


if __name__ == "__main__":  # pragma: no cover
    main()
