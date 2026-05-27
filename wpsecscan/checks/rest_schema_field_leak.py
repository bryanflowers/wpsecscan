"""O144 (v2.6.0) — REST schema-callback field leak.

WordPress REST endpoints registered with a `schema` callback expose the
endpoint's full field structure via `OPTIONS /wp-json/.../endpoint`.
The schema response leaks internal field names + types even when the
GET would fail auth. Several plugins exposed admin-only field names
this way that helped attackers craft targeted UpdatePosts payloads.

Passive: OPTIONS the common REST collections + look for `schema` /
`properties` blocks in the response. Any unauth schema response that
reveals field names (e.g. `wp_admin_*`, `_internal_*`, `secret_*`)
gets flagged.
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding


_PATHS = (
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/settings",
)

_SUSPICIOUS_FIELD = re.compile(
    r'"(?:_?(?:internal|admin|private|secret|api_key|password|token)[a-z0-9_]{0,40})"',
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PATHS:
        step(f"REST schema probe: OPTIONS {path}")
        r = await client.request("OPTIONS", path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        suspicious = sorted(set(_SUSPICIOUS_FIELD.findall(r.text)))
        if suspicious:
            findings.append(Finding(
                severity="medium",
                title=f"REST schema leaks internal/admin field names: {path}",
                evidence=(
                    f"OPTIONS {path} → 200 + suspicious schema keys:\n  "
                    + "\n  ".join(suspicious[:15])
                    + ("\n  ..." if len(suspicious) > 15 else "")
                ),
                remediation=(
                    "1. Audit register_rest_field calls for this endpoint;\n"
                    "   internal-only fields shouldn't be exposed in the schema.\n"
                    "2. Either gate the schema with show_in_rest=>false for\n"
                    "   private fields, or split the endpoint into public +\n"
                    "   private REST namespaces.\n"
                    "3. Confirm the GET response itself doesn't return these\n"
                    "   fields unauthenticated (separate issue if it does)."
                ),
                url=client.url(path),
                extra={"suspicious_fields": suspicious[:15]},
            ))
    return findings
