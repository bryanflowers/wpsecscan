"""A1 (v2.6.0) — AI plugin prompt-injection storage detection.

Several popular WP AI plugins (AI Engine, AIomatic, OpenAI Powered Plugin,
ChatGPT Powered, GPT3 AI Content Generator) read user-controlled fields
— comments, product descriptions, ACF fields, post excerpts — and feed
them into an LLM prompt without sanitising for the prompt-injection
attack surface.

This check is passive: it fingerprints the AI plugin via the rendered
HTML and well-known endpoints, then surfaces a high-severity finding
recommending the operator audit ALL user-content fields the plugin
ingests. The actual exploit is out of scope (requires manual review of
how each plugin templates the user content into the prompt).

Indirect prompt injection has displaced CSRF as the #1 plugin bug class
in 2026 — every AI-enabled WP install needs a manual audit.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# Fingerprints (response-body substring → human-readable plugin name).
_PLUGIN_SIGS = [
    ("ai-engine", "AI Engine"),
    ("mwai-", "AI Engine (Meow AI)"),
    ("aiomatic", "AIomatic"),
    ("/aiomatic-automatic-ai-content-writer/", "AIomatic"),
    ("openai-powered", "OpenAI Powered Plugin"),
    ("chatgpt-powered", "ChatGPT Powered"),
    ("/gpt3-ai-content-generator/", "GPT3 AI Content Generator"),
    ("ai-content-tool", "AI Content Tool"),
    ("ai-mojo", "Ai Mojo"),
    ("kognetiks", "Kognetiks Chatbot"),
]

# REST routes the plugins commonly publish — a 200 here strongly confirms
# the plugin is active even when the homepage HTML doesn't mention it.
_PROBE_ROUTES = (
    "/wp-json/mwai/v1/health",
    "/wp-json/ai-engine/v1/health",
    "/wp-json/aiomatic/v1/status",
    "/wp-json/openai-powered/v1/health",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("AI plugin fingerprint: GET /")
    home = await client.get("/")
    body = (home.text or "").lower() if home else ""

    detected: set[str] = set()
    for sig, name in _PLUGIN_SIGS:
        if sig in body:
            detected.add(name)

    for route in _PROBE_ROUTES:
        step(f"AI plugin probe: {route}")
        r = await client.get(route)
        if r is None or r.status_code not in (200, 401, 403):
            continue
        # 401/403 is still positive evidence the route is registered.
        detected.add(route.split("/")[-2].upper())

    if not detected:
        return findings

    plugin_list = ", ".join(sorted(detected))
    findings.append(Finding(
        severity="high",
        title=f"AI plugin detected ({plugin_list}) — audit prompt-injection surface",
        evidence=(
            f"Detected: {plugin_list}.\n"
            "AI plugins on WordPress commonly templates user-controlled content "
            "(comments, post excerpts, ACF fields, product descriptions) directly "
            "into the LLM prompt without separating the system-prompt from the "
            "user-supplied context. An attacker who can write a comment or product "
            "review can therefore manipulate the LLM's output — exfiltrate data, "
            "issue tool calls, or override the system prompt."
        ),
        remediation=(
            "1. Manually audit every field this plugin reads into the LLM prompt.\n"
            "2. Confirm the plugin separates the system prompt from user content "
            "via the OpenAI / Anthropic role-based API (not string concatenation).\n"
            "3. Disable the plugin on any field that accepts unauthenticated "
            "input (comments, REST POSTs).\n"
            "4. Move to an LLM provider that supports output-filtering / "
            "constitutional-AI safeguards if available."
        ),
        url=str(client.base_url),
        extra={"plugins_detected": sorted(detected),
                "category": "prompt-injection"},
    ))
    return findings
