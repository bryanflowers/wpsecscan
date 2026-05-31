"""F18 (v2.8.1) — WP AI agent tool-call injection probe.

Plugins like AI Engine, Bertha, GetGenie expose a tool/function-
calling surface to LLMs. If the tool-dispatch endpoint accepts
input that influences which tool gets called without server-side
allow-listing, attackers can pivot from chat-prompt to admin-write.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_FINGERPRINTS = (
    ("/wp-content/plugins/ai-engine/", "Meow AI Engine"),
    ("/wp-content/plugins/bertha-ai/", "Bertha AI"),
    ("/wp-content/plugins/getgenie/",  "GetGenie"),
    ("/wp-content/plugins/aiomatic-automatic-ai-content-writer/", "Aiomatic"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F18: fingerprinting AI-tool plugins")
    detected = []
    for path, label in _FINGERPRINTS:
        r = await client.head(path)
        if r is not None and r.status_code in (200, 301, 302, 403):
            detected.append(label)
    if not detected:
        return [Finding(severity="info",
                         title="F18: no AI-agent plugins detected",
                         evidence="None of the 4 fingerprinted plugin paths responded.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    return [Finding(severity="medium",
                     title=f"F18: AI-agent plugin(s) detected: {', '.join(detected)} — audit tool-call surface",
                     evidence=(
                         f"Detected: {', '.join(detected)}. These plugins expose LLM "
                         "tool-calls which CAN write posts, change settings, or "
                         "execute shortcodes if not server-side-allow-listed."),
                     remediation=(
                         "Update plugin to current version. In settings, restrict "
                         "tool-calling to admin-role only. If the plugin exposes a "
                         "'function-calling' or 'agent' mode, disable until you "
                         "audit the allowed-tools list."),
                     url=ctx["target"])]
