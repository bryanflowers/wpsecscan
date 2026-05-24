"""Passive AI/LLM-integration plugin fingerprint.

Round-64 #51 — many WP sites now expose LLM endpoints (AI Engine, GPT-
Chatbot, Bertha AI etc.). Indirect prompt-injection becomes a stored-
XSS-equivalent class of bug. This check fingerprints known LLM plugins
and probes a handful of unauthenticated prompt endpoints, flagging any
that respond without a nonce.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Known WP LLM-plugin slugs + their typical unauth-prompt endpoints.
_LLM_PLUGIN_FINGERPRINTS = (
    ("ai-engine",      "/wp-json/ai-engine/v1/chat"),
    ("aiomatic",       "/wp-json/aiomatic/v1/chat"),
    ("bertha-ai",      "/wp-json/bertha/v1/generate"),
    ("gpt-ai-power",   "/wp-json/gpt/v1/chat"),
    ("gpt3-content-writer", "/wp-json/gpt3/v1/generate"),
    ("woogpt",         "/wp-json/woogpt/v1/answer"),
    ("ai-chatbot",     "/wp-json/ai-chatbot/v1/chat"),
    ("autoblogging",   "/wp-json/autoblog/v1/generate"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    fingerprinted: list[str] = []
    unauth_callable: list[tuple[str, str, int]] = []

    for slug, endpoint in _LLM_PLUGIN_FINGERPRINTS:
        step(f"checking {slug}...")
        # Fingerprint via plugin directory existence
        r = await client.get(f"/wp-content/plugins/{slug}/readme.txt")
        if r is None or r.status_code not in (200, 401, 403):
            continue
        fingerprinted.append(slug)
        # Probe unauthenticated prompt endpoint
        p = await client.post(
            endpoint,
            json={"message": "ping", "prompt": "ping"},
            headers={"Content-Type": "application/json"},
        )
        if p is None:
            continue
        # 200/400 with body that looks like a chat response means
        # unauth users can drive the LLM.
        if p.status_code in (200, 400) and len(p.text or "") > 20:
            unauth_callable.append((slug, endpoint, p.status_code))

    if fingerprinted:
        findings.append(
            Finding(
                severity="info",
                title=f"AI/LLM-integration plugins detected: {', '.join(fingerprinted)}",
                evidence=f"{len(fingerprinted)} LLM plugin(s) fingerprinted via /wp-content/plugins/<slug>/readme.txt",
                remediation=(
                    "Indirect prompt-injection is now a real attack surface for LLM-integrated WP plugins.\n"
                    "Review each plugin's settings for: anonymous-prompt allowed? rate limited? output sanitised?\n"
                    "Treat LLM output rendered into pages as untrusted (CSP + escaping)."
                ),
                url=client.url("/wp-content/plugins/"),
                extra={"plugins": fingerprinted},
            )
        )

    for slug, endpoint, status in unauth_callable:
        findings.append(
            Finding(
                severity="high",
                title=f"Unauthenticated LLM prompt endpoint reachable: {slug}",
                evidence=f"POST {endpoint} -> {status} (no nonce / no auth required)",
                remediation=(
                    "Restrict the prompt endpoint behind an auth check (cookie + nonce).\n"
                    "Add rate limiting (per-IP + per-token-burn budget).\n"
                    "Without these, the endpoint is both a free LLM proxy for attackers AND a stored-prompt-injection vector for your site's own pages."
                ),
                url=client.url(endpoint),
                extra={"plugin": slug},
            )
        )

    return findings
