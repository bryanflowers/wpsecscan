"""A27 (v2.6.0) — Polylang / WPML / TranslatePress / WeGlot API-key leak.

Translation plugins use Google Translate / DeepL / Azure Translator to
machine-translate content. The API key is stored in wp_options and is
SUPPOSED to be server-side only — but several plugins exposed it via:

  • A REST endpoint that returned the option's value for any logged-in
    user (CVE family in 2024).
  • A JS settings page that leaked the key into the rendered form via
    value="..." (saved-and-redisplayed pattern).
  • Frontend translate-on-the-fly widgets where the key is loaded into
    a window-global.

Passive: scan the homepage + admin login page (which sometimes loads
plugin JS) for Google/DeepL/Azure-Translator API key patterns.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# Conservative key patterns:
#   Google Cloud API keys: AIzaSy + 33 chars
#   DeepL: 36 chars + ":fx" for free plans
#   Azure Translator: 32 hex chars in an Ocp-Apim-Subscription-Key header
_PATTERNS = (
    (re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "Google Cloud Translation API"),
    (re.compile(r"\b([0-9a-f-]{36}:fx)\b"), "DeepL API (free)"),
    (re.compile(r"\b([0-9a-f-]{36})\b\s*(?:authKey|deeplKey)", re.IGNORECASE), "DeepL API (pro)"),
    (re.compile(r"Ocp-Apim-Subscription-Key[\"'\s:]+[\"']([0-9a-f]{32})", re.IGNORECASE), "Azure Translator"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in ("/", "/wp-login.php"):
        step(f"translation-key scan: {path}")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for rx, provider in _PATTERNS:
            for m in rx.finditer(r.text):
                key = m.group(1)
                findings.append(Finding(
                    severity="high",
                    title=f"{provider} API key leaked into public page",
                    evidence=(
                        f"GET {path} body contains a {provider} key (prefix: {key[:8]}...)\n"
                        f"Pattern matched at offset {m.start()}.\n"
                        "Translation API keys grant access to a paid quota; an "
                        "attacker can drain it to inflate the operator's bill."
                    ),
                    remediation=(
                        f"1. REVOKE the {provider} key NOW at the provider's console.\n"
                        "2. Issue a new key, store it ONLY in wp-config.php or a\n"
                        "   .env file the WP plugin reads server-side.\n"
                        "3. Update the translation plugin to a version that\n"
                        "   doesn't render the key into HTML/JS.\n"
                        "4. Set provider-side billing alerts at 25%/50%/100% of quota."
                    ),
                    url=client.url(path),
                    extra={"provider": provider, "key_prefix": key[:8]},
                ))
                return findings  # one critical leak is enough
    return findings
