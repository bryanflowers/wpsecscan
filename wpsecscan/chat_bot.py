"""M38 Slack / Discord chat bot adapter.

Translates Slack or Discord slash-command webhooks into scan triggers,
then formats the result as a chat message and posts back.

This module is a translation layer — it doesn't run a long-lived bot
process. Two integration patterns:

  1. Slack slash command:
     POST /slack/cmd  body=urlencoded form
     -> call handle_slack(form_dict) -> returns dict to be JSONified

  2. Discord interaction webhook:
     POST /discord/interaction body=json
     -> call handle_discord(json_payload) -> returns dict

Wire either into the api_server (M34) by adding routes that call these
handlers. The handlers themselves spawn the scan in a background thread
and return immediate "ack" payloads so the chat platform doesn't time out.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any


def _scan_and_format(target: str, aggressive: bool = False) -> dict:
    """Run a synchronous scan and produce a chat-friendly summary dict."""
    from . import scanner

    async def _go():
        return await scanner.scan(target=target, aggressive=aggressive)

    try:
        report = asyncio.run(_go())
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    s = report.summary
    return {
        "ok": True,
        "target": target,
        "risk_score": int(report.risk_score),
        "critical": s.get("critical", 0),
        "high": s.get("high", 0),
        "medium": s.get("medium", 0),
        "duration_ms": report.duration_ms,
    }


def _slack_summary_blocks(result: dict) -> list[dict]:
    if not result.get("ok"):
        return [{"type": "section", "text": {"type": "mrkdwn",
                "text": f":x: Scan failed: `{result.get('error', '?')}`"}}]
    risk = result["risk_score"]
    emoji = ":white_check_mark:" if risk >= 90 else (":warning:" if risk >= 70 else ":rotating_light:")
    return [
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"{emoji} *WPSecScan result for `{result['target']}`*"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Risk score*\n{risk}/100"},
            {"type": "mrkdwn", "text": f"*Duration*\n{result['duration_ms']} ms"},
            {"type": "mrkdwn", "text": f"*Critical*\n{result['critical']}"},
            {"type": "mrkdwn", "text": f"*High*\n{result['high']}"},
        ]},
    ]


def handle_slack(form: dict[str, Any]) -> dict:
    """Slack slash-command handler.

    form keys (from Slack): `command`, `text`, `user_name`, `response_url`...
    `text` is the user-supplied argument, e.g. "https://example.com aggressive".
    Returns the in_channel ack message; the full result is posted via response_url.
    """
    raw = (form.get("text") or "").strip()
    parts = raw.split()
    if not parts:
        return {"response_type": "ephemeral",
                "text": "Usage: `/wpsec <url> [aggressive]`"}
    target = parts[0]
    aggressive = len(parts) > 1 and parts[1].lower() == "aggressive"
    response_url = form.get("response_url", "")

    def _do_scan_and_followup():
        result = _scan_and_format(target, aggressive=aggressive)
        if response_url:
            try:
                import urllib.request, json as _j
                body = _j.dumps({
                    "response_type": "in_channel",
                    "blocks": _slack_summary_blocks(result),
                }).encode("utf-8")
                req = urllib.request.Request(response_url, data=body,
                                              headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5.0)
            except Exception:  # noqa: BLE001
                pass

    threading.Thread(target=_do_scan_and_followup, daemon=True).start()
    return {"response_type": "ephemeral",
            "text": f"Scan started for `{target}`{' (aggressive)' if aggressive else ''}. Results in a moment..."}


def handle_discord(payload: dict[str, Any]) -> dict:
    """Discord interaction webhook handler.

    Returns an immediate "type 5" (deferred response) if interaction is a
    slash command, else a type-1 PING response."""
    if payload.get("type") == 1:
        return {"type": 1}  # PING
    if payload.get("type") == 2:  # APPLICATION_COMMAND
        data = payload.get("data") or {}
        options = {o.get("name"): o.get("value") for o in (data.get("options") or [])}
        target = options.get("url") or ""
        aggressive = bool(options.get("aggressive"))
        if not target:
            return {"type": 4, "data": {"content": "Missing `url` parameter."}}

        def _do_scan_and_followup():
            result = _scan_and_format(target, aggressive=aggressive)
            msg = f"**WPSecScan result for** `{result.get('target', '?')}`\n" \
                  f"Risk score: **{result.get('risk_score', '?')}/100**\n" \
                  f"Critical: {result.get('critical', 0)} · " \
                  f"High: {result.get('high', 0)} · " \
                  f"Medium: {result.get('medium', 0)}"
            app_id = payload.get("application_id")
            token = payload.get("token")
            if app_id and token:
                try:
                    import urllib.request, json as _j
                    body = _j.dumps({"content": msg}).encode("utf-8")
                    req = urllib.request.Request(
                        f"https://discord.com/api/v10/webhooks/{app_id}/{token}",
                        data=body, headers={"Content-Type": "application/json"},
                    )
                    urllib.request.urlopen(req, timeout=5.0)
                except Exception:  # noqa: BLE001
                    pass

        threading.Thread(target=_do_scan_and_followup, daemon=True).start()
        return {"type": 5}  # deferred channel-message
    return {"type": 4, "data": {"content": "Unsupported interaction type."}}
