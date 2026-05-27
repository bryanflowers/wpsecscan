"""O142 (v2.6.0) — HTML-API rewriting breaks CSP nonces.

WP 6.7 ships the HTML API for tag-level rewriting in PHP. Themes that
post-process the rendered HTML via `WP_HTML_Tag_Processor::next_tag()`
sometimes drop CSP nonce attributes from inline scripts (the API
preserves attributes by default but custom callbacks can mutate them).

When the page sends a strict CSP with `script-src 'nonce-...'`, any
inline <script> that lost its nonce is blocked at runtime — breaking
functionality silently. Conversely, if a theme INJECTS scripts without
nonces, the operator may be tempted to weaken the CSP to fix it.

Passive: GET /, compare:
  - CSP header script-src directive
  - inline <script> tags' nonce= attribute presence
Flag medium when CSP requires a nonce but some inline scripts lack it.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_INLINE_SCRIPT_RE = re.compile(
    r'<script\b([^>]*)>',
    re.IGNORECASE,
)
_SRC_ATTR_RE = re.compile(r'\bsrc\s*=', re.IGNORECASE)
_NONCE_ATTR_RE = re.compile(r"\bnonce\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("CSP nonce vs inline-script audit")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    csp = r.headers.get("content-security-policy", "")
    if "nonce-" not in csp:
        return findings  # CSP doesn't use nonces — nothing to verify

    inline_no_nonce = 0
    inline_with_nonce = 0
    examples: list[str] = []
    for m in _INLINE_SCRIPT_RE.finditer(r.text):
        attrs = m.group(1)
        if _SRC_ATTR_RE.search(attrs):
            continue  # external script — different CSP rule
        if _NONCE_ATTR_RE.search(attrs):
            inline_with_nonce += 1
        else:
            inline_no_nonce += 1
            if len(examples) < 5:
                examples.append(attrs.strip()[:120] or "(no attrs)")

    if inline_no_nonce > 0:
        findings.append(Finding(
            severity="medium",
            title=f"CSP requires script nonces but {inline_no_nonce} inline <script> tag(s) have no nonce",
            evidence=(
                f"CSP header includes nonce-... directive.\n"
                f"Inline <script> tags WITH nonce: {inline_with_nonce}\n"
                f"Inline <script> tags WITHOUT nonce: {inline_no_nonce}\n"
                f"Examples (first 5):\n  " + "\n  ".join(examples)
            ),
            remediation=(
                "1. Check whether a theme's HTML-API mutator is stripping the\n"
                "   nonce attribute (look for WP_HTML_Tag_Processor calls).\n"
                "2. If injected without nonce: have the theme use wp_get_script_nonce()\n"
                "   (or its equivalent) at render time.\n"
                "3. DO NOT weaken the CSP to 'unsafe-inline' as a workaround —\n"
                "   that defeats the whole nonce strategy."
            ),
            url=client.url("/"),
            extra={"inline_with_nonce": inline_with_nonce,
                    "inline_no_nonce": inline_no_nonce},
        ))
    return findings
