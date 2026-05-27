"""A2 (v2.6.0) — AI chatbot webhook leak.

Modern WP chatbot plugins (AI Engine, WPBot, BotPenguin, Tidio, Crisp)
POST conversation transcripts to an LLM provider via a stored webhook
URL. When that URL or the plugin's relay endpoint is unauthenticated,
anyone can:

  • Exfil past conversations (privacy + competitive intelligence leak).
  • Replay conversations to inflate the operator's OpenAI bill.
  • Inject crafted prompts into the next conversation.

Passive: probe the common relay endpoints + scan the homepage HTML for
inline-script `apiUrl` / `webhookUrl` properties that leak the key.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# Common chatbot-relay endpoints that get registered in wp-json.
_RELAY_ROUTES = (
    "/wp-json/mwai/v1/chats/submit",       # AI Engine
    "/wp-json/ai-engine/v1/chat",          # AI Engine (older path)
    "/wp-json/wpbot/v1/conversations",     # WPBot
    "/wp-json/botpenguin/v1/chat",         # BotPenguin
    "/wp-json/tidio/v1/relay",             # Tidio
    "/wp-json/crisp/v1/conversation",      # Crisp
)

# Inline-script properties that frequently leak the upstream key.
_LEAK_RE = re.compile(
    r"(?:apiUrl|webhookUrl|relayUrl|chatEndpoint|openaiKey|anthropicKey)"
    r"\s*[:=]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("AI chatbot: probe relay endpoints")
    for route in _RELAY_ROUTES:
        r = await client.post(route, json={"message": "ping"})
        if r is None or r.status_code in (404, 401, 403):
            continue
        if r.status_code < 500:
            findings.append(Finding(
                severity="high",
                title=f"AI chatbot relay endpoint accepts unauthenticated POST: {route}",
                evidence=(
                    f"POST {route} → HTTP {r.status_code}.\n"
                    f"Body (truncated): {(r.text or '')[:200]}"
                ),
                remediation=(
                    f"Require authentication on the relay endpoint. In the plugin's\n"
                    f"register_rest_route() call, set 'permission_callback' to a\n"
                    f"function that verifies the request's nonce + capability.\n"
                    f"Until then, block POST {route} at the WAF."
                ),
                url=client.url(route),
                extra={"endpoint": route, "status": r.status_code},
            ))

    step("AI chatbot: scan homepage for inline-key leaks")
    home = await client.get("/")
    if home and home.text:
        for m in _LEAK_RE.finditer(home.text):
            value = m.group(1)
            # Filter out obvious site-internal URLs to reduce false positives.
            if value.startswith(("/", client.base_url)):
                continue
            findings.append(Finding(
                severity="medium",
                title="AI chatbot config leaks upstream URL or key into frontend JS",
                evidence=(
                    f"Inline JS contains: {m.group(0)[:200]}\n"
                    f"Leaked value: {value[:120]}"
                ),
                remediation=(
                    "Move the upstream URL / API key out of the page-rendered JS\n"
                    "into a server-side AJAX relay. Frontend code should call your\n"
                    "own /wp-json/.../chat endpoint, which forwards to the LLM\n"
                    "provider with a server-held key."
                ),
                url=client.url("/"),
                extra={"leak": value[:200]},
            ))

    return findings
