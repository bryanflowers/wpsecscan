"""A5 (v2.6.0) — Gutenberg Block-Bindings exposure.

Gutenberg 6.5+ added the Block Bindings API: a block attribute can be
bound to a PHP source (post meta, post property, custom callback) via
the `metadata.bindings` field in block markup. The default sources
are `core/post-meta` and `core/pattern-overrides`; plugins register
their own sources via `register_block_bindings_source()`.

Two known bug classes:

  • A custom bindings-source callback that reads a meta key but
    doesn't restrict by post type can leak private-post meta to the
    public frontend.
  • A bindings source registered without `uses_context` validation
    can be invoked from contexts the developer didn't anticipate.

Passive: scan the rendered HTML for `metadata.bindings` references +
serialised block markup containing `<!-- wp:` ... `metadata":{
"bindings":{` patterns. Flag any custom (non-core) source name as
"audit required".
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


# Bindings JSON literal in serialised block markup:
#   <!-- wp:paragraph {"metadata":{"bindings":{"content":{"source":"foo/bar","args":{...}}}}} -->
_BINDING_RE = re.compile(
    r'"bindings"\s*:\s*\{[^}]*"source"\s*:\s*"([a-zA-Z0-9_/-]+)"',
)

# Core sources are safe-by-default; custom ones need audit.
_KNOWN_CORE_SOURCES = frozenset({
    "core/post-meta", "core/pattern-overrides", "core/site-data",
})


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Block-Bindings scan: GET /")
    home = await client.get("/")
    html = (home.text or "") if home else ""

    custom_sources: set[str] = set()
    for m in _BINDING_RE.finditer(html):
        src = m.group(1)
        if src not in _KNOWN_CORE_SOURCES:
            custom_sources.add(src)

    if custom_sources:
        findings.append(Finding(
            severity="medium",
            title=f"Custom Block-Bindings sources in use: {', '.join(sorted(custom_sources))}",
            evidence=(
                f"Rendered HTML contains Block-Bindings references to non-core sources:\n"
                f"  {', '.join(sorted(custom_sources))}\n"
                f"Custom bindings-source callbacks have leaked private post meta\n"
                f"to the public frontend when the registration didn't validate\n"
                f"post type or capability. Manual audit required."
            ),
            remediation=(
                "1. For each listed source, locate the plugin's "
                "register_block_bindings_source() call.\n"
                "2. Verify the source's `get_value_callback` checks the post type "
                "and the current user's capability before returning the value.\n"
                "3. If the callback reads from post meta, restrict to whitelisted "
                "meta keys — never pass user-supplied key names through.\n"
                "4. Add 'uses_context' => [...] so the source only runs in the "
                "block contexts the developer intended."
            ),
            url=client.url("/"),
            extra={"custom_sources": sorted(custom_sources)},
        ))

    return findings
