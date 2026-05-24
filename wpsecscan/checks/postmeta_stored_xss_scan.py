"""Stored-XSS scan of post_meta exposed via REST.

Round-64 #54 — many plugins write attacker-controllable data into
post_meta and then expose it via /wp-json/wp/v2/posts?_embed=true. If
the value is rendered HTML, the resulting field appears intact. We pull
the most recent N posts, walk their `.meta` field, and flag any value
that contains an unescaped <script> tag (the canonical "this is
stored-XSS in the wild" signal).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Conservative — only flag the most obvious renderable payload patterns.
# Avoid f.p. on innocent code-listings by requiring `=` style attributes.
_XSS_PATTERNS = (
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"on(?:click|load|error|mouseover)\s*=\s*['\"]", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"<iframe[^>]*src\s*=", re.IGNORECASE),
)

MAX_POSTS = 30


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("fetching /wp-json/wp/v2/posts...")
    r = await client.get(f"/wp-json/wp/v2/posts?per_page={MAX_POSTS}&_fields=id,link,meta")
    if r is None or r.status_code != 200:
        return findings
    try:
        posts = r.json()
    except (ValueError, TypeError):
        return findings
    if not isinstance(posts, list):
        return findings

    flagged: list[dict] = []
    for p in posts:
        meta = p.get("meta") if isinstance(p, dict) else None
        if not isinstance(meta, dict):
            continue
        for key, value in meta.items():
            if not isinstance(value, str):
                continue
            for pat in _XSS_PATTERNS:
                if pat.search(value):
                    flagged.append({
                        "post_id": p.get("id"),
                        "link": p.get("link"),
                        "meta_key": key,
                        "snippet": value[:120],
                    })
                    break

    if flagged:
        findings.append(
            Finding(
                severity="critical",
                title=f"Stored-XSS-shaped content in post_meta ({len(flagged)} match)",
                evidence=(
                    "Matches (first 5):\n  "
                    + "\n  ".join(
                        f"post {m['post_id']} meta[{m['meta_key']!r}]: {m['snippet']!r}"
                        for m in flagged[:5]
                    )
                ),
                remediation=(
                    "Either:\n"
                    "  (a) These are LIVE stored-XSS payloads from a compromised input — view the affected posts in an isolated browser, remove the payload, and audit how it landed there.\n"
                    "  (b) A plugin is legitimately storing HTML in meta and exposing it to the world (rare and bad). Hide the meta from REST via `register_meta(..., 'show_in_rest' => false)`."
                ),
                url=client.url("/wp-json/wp/v2/posts"),
                extra={"matches": flagged[:20]},
            )
        )

    return findings
