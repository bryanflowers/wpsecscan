"""Detect unauthenticated chat-log / conversation endpoints from popular
WordPress AI-chatbot plugins.

Plugins like Tidio, WP-Chatbot, AI Chat Elfsight, BotPenguin, AI Engine,
ChatBot for WordPress expose REST endpoints for chat history. When those
endpoints don't authenticate, visitor PII (names, emails, message
content) leaks. GDPR/CCPA reportable.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_PROBES = (
    "/wp-json/tidio/v1/messages",
    "/wp-json/tidio/v1/conversations",
    "/wp-json/wpforms-ai/v1/chat",
    "/wp-json/chatbot/v1/conversations",
    "/wp-json/ai-engine/v1/chat",
    "/wp-json/botpenguin/v1/conversations",
    "/wp-json/elfsight/v1/chat",
    "/wp-json/wpc-chatbot/v1/sessions",
    "/wp-json/chatgpt-wp/v1/history",
)

_PII_MARKERS = re.compile(
    r'"(?:user_email|customer_email|visitor_email|email|messages?|conversation_id|chat_id|message_text|visitor_name)"',
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    leaked: list[tuple[str, int]] = []
    for path in _PROBES:
        step(f"probing AI-chatbot endpoint {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        text = r.text[:5000]
        # Must look like JSON (chat APIs always JSON)
        if not (text.lstrip().startswith("{") or text.lstrip().startswith("[")):
            continue
        marker_count = len(_PII_MARKERS.findall(text))
        if marker_count >= 1:
            leaked.append((path, marker_count))
    if not leaked:
        return findings
    lines = "\n".join(f"  - {p} ({n} PII-shaped key(s))" for p, n in leaked)
    findings.append(Finding(
        severity="critical",
        title=f"AI-chatbot endpoint(s) leak conversation data unauthenticated ({len(leaked)})",
        evidence=(
            f"Endpoints returning chat/conversation data without auth:\n{lines}\n\n"
            "JSON keys like `user_email`, `messages`, `conversation_id`, "
            "`visitor_name` indicate the endpoint is exposing real conversations. "
            "Every visitor who has ever talked to your site's chatbot is now "
            "enumerable by anyone."
        ),
        remediation=(
            "1. IMMEDIATELY: disable or restrict the offending plugin's REST "
            "namespace via the `rest_endpoints` filter, OR uninstall the plugin.\n"
            "2. Assess GDPR/CCPA scope: chat content is personal data. Calculate "
            "the exposure window from access logs.\n"
            "3. File a security report with the plugin author and check WPScan / "
            "Patchstack for a known CVE in the plugin's version."
        ),
        url=ctx["target"],
        extra={"exposed_endpoints": [p for p, _ in leaked]},
    ))
    return findings
