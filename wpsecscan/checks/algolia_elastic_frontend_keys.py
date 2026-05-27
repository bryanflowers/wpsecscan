"""A14 (v2.6.0) — Algolia / Elasticsearch write-key leak via frontend JS.

algoliasearch-wordpress publishes a search-only API key into the
frontend bundle (intentional, safe), but mis-configured installs push
the ADMIN key (write/delete access on the index) instead. Same story
for `elasticpress` when the operator copy-pastes the wrong key into
the plugin's Settings page.

Passive: scan the homepage + the plugin's known JS-config endpoints
for the canonical key-shaped strings and flag any value whose ACL
field reveals write/admin scope (Algolia keys are base64-encoded JSON
blobs that include the ACL).
"""
from __future__ import annotations

import base64
import binascii
import json
import re

from ..http import Client
from ..models import Finding


_KEY_RES = (
    re.compile(r'algoliaApiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']', re.IGNORECASE),
    re.compile(r'algoliasearch[^"]*apiKey["\']?\s*:\s*["\']([A-Za-z0-9+/=]{16,})["\']', re.IGNORECASE),
    re.compile(r'elasticsearch[^"]*apiKey["\']?\s*:\s*["\']([A-Za-z0-9+/=:_-]{16,})["\']', re.IGNORECASE),
    re.compile(r'(?:meilisearch|typesense)ApiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{16,})["\']', re.IGNORECASE),
)

_ADMIN_ACLS = ("addObject", "deleteObject", "deleteIndex", "settings",
                "editSettings", "admin", "all")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Algolia/ES key extraction: GET /")
    home = await client.get("/")
    html = (home.text or "") if home else ""

    found: list[tuple[str, str]] = []  # (engine, key)
    for rx in _KEY_RES:
        for m in rx.finditer(html):
            found.append(("frontend-extracted", m.group(1)))

    for engine, key in found:
        is_admin = False
        # Algolia search keys are base64 JSON with `validUntil` and `acl` fields.
        if len(key) > 24 and "=" in key:
            try:
                payload = base64.b64decode(key + "==").decode("utf-8", errors="replace")
                if any(acl in payload for acl in _ADMIN_ACLS):
                    is_admin = True
            except (binascii.Error, ValueError):
                pass

        sev = "critical" if is_admin else "low"
        title = (
            "Algolia/ES ADMIN API key leaked into frontend JS — index write/delete possible"
            if is_admin
            else "Algolia/ES API key visible in frontend JS (verify it's search-only)"
        )
        findings.append(Finding(
            severity=sev,
            title=title,
            evidence=(
                f"Engine: {engine}\n"
                f"Key (first 16 chars): {key[:16]}...\n"
                f"Admin-scope detected: {is_admin}"
            ),
            remediation=(
                "1. Open the search-engine dashboard, list this key's ACL.\n"
                "2. If it's anything other than `search` (Algolia) / "
                "`read-only` (ES/Meili/Typesense), REVOKE NOW and replace "
                "the frontend usage with a search-only key.\n"
                "3. Confirm the plugin's Settings page separates the admin "
                "key (server-side .env) from the search key (frontend JS)."
            ),
            url=client.url("/"),
            extra={"key_prefix": key[:16], "admin_acl": is_admin},
        ))
    return findings
