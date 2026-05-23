"""H9 Plugin-route fuzzer.

Extends the existing plugin enumeration: for every detected plugin slug,
probe its known unauthenticated REST endpoints (sourced from a curated
mapping). Catches the long tail of "this plugin exposes /wp-json/foo/v1/
without an auth check" — about 30% of WordPress sites run at least one.

We're conservative: only GET probes (no writes), only `info` severity for
"endpoint accessible" findings; the severity bumps to `medium`/`high` if
the response body matches a known data-leak signature.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..http import Client
from ..models import Finding

# Curated map: plugin_slug -> [(path, leak_signature_re | None)]
# Path uses {target} substitution. Conservative — only well-known endpoints.
PLUGIN_ROUTES = {
    "contact-form-7": [
        ("/wp-json/contact-form-7/v1/contact-forms", "form-tag"),
    ],
    "wpforms-lite": [
        ("/wp-json/wpforms/v1/forms", "form_id"),
    ],
    "elementor": [
        ("/wp-json/elementor/v1/site-mailer/send", None),  # POST endpoint; just probe GET to see if disclosed
    ],
    "wordpress-seo": [
        ("/wp-json/yoast/v1/configuration/site_representation", None),
        ("/wp-json/yoast/v1/indexable", None),
    ],
    "woocommerce": [
        ("/wp-json/wc/store/products", "products"),
        ("/wp-json/wc/store/cart", "items"),
    ],
    "akismet": [
        ("/wp-json/akismet/v1/key", None),
    ],
    "jetpack": [
        ("/wp-json/jetpack/v4/sites", None),
        ("/wp-json/jetpack/v4/connection", "isActive"),
    ],
    "polylang": [
        ("/wp-json/pll/v1/languages", "name"),
    ],
    "advanced-custom-fields": [
        ("/wp-json/acf/v3/posts", None),
    ],
    "buddypress": [
        ("/wp-json/buddypress/v1/members", "user_login"),
        ("/wp-json/buddypress/v1/activity", "user_id"),
    ],
    "the-events-calendar": [
        ("/wp-json/tribe/events/v1/events", "events"),
    ],
    "litespeed-cache": [
        ("/wp-json/litespeed/v3/info", None),
    ],
    "wp-fastest-cache": [
        ("/wp-json/wpfc/v1/status", None),
    ],
    "all-in-one-seo-pack": [
        ("/wp-json/aioseo/v1/objects", None),
    ],
    "redirection": [
        ("/wp-json/redirection/v1/redirect", "items"),
    ],
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Pull discovered plugins from the shared bus (plugins check populates this)
    shared = ctx.get("shared") or {}
    plugins = shared.get("plugins") or []
    if not plugins:
        findings.append(Finding(
            severity="info",
            title="Plugin-route fuzzer skipped (no plugins detected)",
            evidence="The plugins check didn't enumerate any plugin slugs to probe.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # plugins is a list of dicts: [{"slug": "woocommerce", "version": "9.2.1"}, ...]
    slugs = {p.get("slug") for p in plugins if isinstance(p, dict) and p.get("slug")}
    matched = {s for s in slugs if s in PLUGIN_ROUTES}
    if not matched:
        findings.append(Finding(
            severity="info",
            title=f"Plugin-route fuzzer — none of the {len(slugs)} detected plugin(s) has known routes",
            evidence="The detected plugins aren't in our curated mapping. Add custom signatures via ~/.wpsecscan/signatures/.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    reachable: list[tuple[str, str, int, int]] = []  # (slug, path, status, len)
    leaks: list[tuple[str, str, str]] = []           # (slug, path, signature)
    for slug in sorted(matched):
        for path, signature in PLUGIN_ROUTES[slug]:
            step(f"probing {slug}: {path}...")
            r = await client.get(path)
            if r is None:
                continue
            if 200 <= r.status_code < 300:
                reachable.append((slug, path, r.status_code, len(r.content or b"")))
                if signature:
                    body = (r.text or "")[:5000].lower()
                    if signature.lower() in body:
                        leaks.append((slug, path, signature))

    if leaks:
        findings.append(Finding(
            severity="high",
            title=f"Unauthenticated plugin endpoints leaking data — {len(leaks)} confirmed",
            evidence="\n".join(f"  - {s} {p}: matched signature '{sig}'" for s, p, sig in leaks),
            remediation=(
                "These REST endpoints respond to unauthenticated requests with structured data that "
                "matches the plugin's data shape. Audit the plugin's `register_rest_route` definitions — "
                "every route should declare a `permission_callback`. Default-deny: "
                "`'permission_callback' => function() { return current_user_can('read'); }`."
            ),
            url=ctx["target"],
        ))

    if reachable and not leaks:
        findings.append(Finding(
            severity="medium",
            title=f"{len(reachable)} plugin endpoint(s) accessible unauthenticated (no data leak signature)",
            evidence="\n".join(f"  - {s} {p} -> HTTP {st} ({sz} bytes)" for s, p, st, sz in reachable[:15]),
            remediation=(
                "Endpoints respond 2xx unauthenticated. Whether that's intentional depends on the plugin's "
                "design — confirm by reading the plugin's REST route definitions. Add a "
                "`permission_callback` to enforce authentication if not intended."
            ),
            url=ctx["target"],
        ))
    return findings
