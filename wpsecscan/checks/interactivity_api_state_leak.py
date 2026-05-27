"""A6 (v2.6.0) — Interactivity-API state leak.

WP 6.5+ ships the `@wordpress/interactivity` runtime: blocks declare
client-side state and actions via `data-wp-context`, `data-wp-bind`,
`data-wp-on`, etc. directives. The full server state often gets
serialised into the page's `<script type="application/json"
id="wp-interactivity-data">` blob so the runtime can hydrate it.

Two patterns leak server state:

  • `data-wp-context='{"user_email":"foo@bar.com",…}'` on an element
    rendered by a personalisation plugin.
  • The wp-interactivity-data JSON blob containing user IDs, internal
    URLs, or feature-flag names.

Passive: scan the homepage for inline JSON state and flag any
high-signal keys (`email`, `phone`, `address`, `ssn`, `api_key`).
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding


_PII_KEYS = (
    "email", "e-mail", "phone", "tel", "address", "ssn",
    "national_id", "passport", "api_key", "apikey", "token",
    "secret", "password", "credit_card", "card_number",
    "billing_address", "shipping_address",
)

_CTX_RE = re.compile(
    r'data-wp-context\s*=\s*(["\'])(\{[^"\']{1,2000}?\})\1',
    re.IGNORECASE,
)
_BLOB_RE = re.compile(
    r'<script[^>]*id\s*=\s*["\']wp-interactivity-data["\'][^>]*>'
    r'(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def _scan_for_pii(blob: str) -> list[str]:
    hits = []
    low = blob.lower()
    for key in _PII_KEYS:
        if f'"{key}"' in low or f"'{key}'" in low:
            hits.append(key)
    return hits


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Interactivity-API state scan: GET /")
    home = await client.get("/")
    html = (home.text or "") if home else ""

    # 1. data-wp-context inline JSON
    for m in _CTX_RE.finditer(html):
        raw = m.group(2)
        pii = _scan_for_pii(raw)
        if pii:
            findings.append(Finding(
                severity="high",
                title="Interactivity API context leaks PII-shaped keys",
                evidence=(
                    f"data-wp-context blob contains keys: {', '.join(pii)}\n"
                    f"Excerpt: {raw[:300]}"
                ),
                remediation=(
                    "Move the leaked fields out of data-wp-context (server-rendered "
                    "into the HTML) into a separate authenticated /wp-json/ endpoint "
                    "the runtime fetches AFTER login. The Interactivity runtime "
                    "should only hold non-PII state in the client-visible JSON."
                ),
                url=client.url("/"),
                extra={"pii_keys": pii},
            ))

    # 2. wp-interactivity-data blob
    blob_match = _BLOB_RE.search(html)
    if blob_match:
        blob = blob_match.group(1).strip()
        try:
            data = json.loads(blob) if blob else {}
        except json.JSONDecodeError:
            data = {}
        pii = _scan_for_pii(blob)
        if pii:
            findings.append(Finding(
                severity="high",
                title="Interactivity-API hydration blob leaks PII-shaped keys",
                evidence=(
                    f"<script id='wp-interactivity-data'> contains keys: {', '.join(pii)}\n"
                    f"Blob size: {len(blob)} bytes\n"
                    f"First 300 bytes: {blob[:300]}"
                ),
                remediation=(
                    "Audit which plugins push state into wp_initial_state(). For\n"
                    "per-user data, fetch it via an authenticated REST request\n"
                    "after the page loads rather than embedding into HTML.\n"
                    "Run `wp interactivity-config audit` if WP-CLI extension exists."
                ),
                url=client.url("/"),
                extra={"pii_keys": pii, "blob_size": len(blob)},
            ))

    return findings
