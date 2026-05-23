"""#8 (from wpscan) — XML-RPC hidden-method brute-force.

`xmlrpc.php` lets plugins register custom methods alongside the WP-core
methods. `system.listMethods` usually returns them, but some plugins hide
methods from the listing while still exposing them. wpscan brute-forces
~200 method-name candidates to find these.

We send `<methodCall><methodName>X</methodName>...</methodCall>` for each
candidate name; a `faultCode -32601 "method does not exist"` means it
truly doesn't, any other response (auth required, malformed-params,
success) means the method IS registered.

Passive — single GET to confirm xmlrpc.php is enabled before brute-forcing.
"""
from __future__ import annotations

import asyncio

from ..http import Client
from ..models import Finding


# Methods that wpscan & common pentest checklists probe for
CANDIDATE_METHODS = (
    # WP-core (should all be visible via listMethods; included as a control)
    "system.listMethods", "system.methodHelp",
    # Jetpack
    "jetpack.testConnection", "jetpack.featuresAvailable", "jetpack.featuresEnabled",
    "jetpack.identityCrisis", "jetpack.getSitemap", "jetpack.getCredentials",
    # WooCommerce
    "wc.getOrders", "wc.getCustomers", "wc.getProducts",
    # Akismet
    "akismet.verifyKey", "akismet.checkComment",
    # JSON-API legacy plugins
    "json_api.get_info", "json_api.get_posts",
    # Custom "internal" plugins (common naming patterns)
    "internal.debug", "internal.dumpConfig", "internal.exec", "internal.shell",
    "admin.invoke", "admin.execSql", "admin.debug",
    "private.getKey", "private.getToken",
    # Polylang / WPML
    "pll.getLanguages", "wpml.getLanguages",
    # BackupBuddy / UpdraftPlus
    "backupbuddy.run", "updraftplus.run", "updraftplus.dumpConfig",
    # WP Super Cache / W3 Total Cache
    "wp_cache.flush", "w3tc.flush", "w3tc.clear_all",
    # Generic stubs
    "test.fn", "test.echo", "debug.config", "debug.eval", "debug.run",
)
FAULT_NO_METHOD = "-32601"


def _build_call(method: str) -> bytes:
    return (f"<?xml version='1.0'?><methodCall><methodName>{method}</methodName>"
            "<params></params></methodCall>").encode("utf-8")


async def _probe(client: Client, method: str) -> tuple[str, int, bool] | None:
    r = await client.request("POST", "/xmlrpc.php",
                              content=_build_call(method),
                              headers={"Content-Type": "text/xml"})
    if r is None:
        return None
    body = (r.text or "")[:2000]
    # We treat anything that's NOT the "method does not exist" fault as "method IS registered"
    is_registered = (FAULT_NO_METHOD not in body)
    return (method, r.status_code, is_registered)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("checking xmlrpc.php availability...")
    head = await client.get("/xmlrpc.php")
    if head is None or head.status_code in (403, 404, 410):
        findings.append(Finding(
            severity="info",
            title="XML-RPC method brute-force skipped (xmlrpc.php not accessible)",
            evidence=f"GET /xmlrpc.php returned {head.status_code if head else 'no response'}.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    step(f"XML-RPC method brute ({len(CANDIDATE_METHODS)} candidates)...")
    # Limit concurrency so we don't hammer a small WP site
    sem = asyncio.Semaphore(3)
    async def _bounded(m: str):
        async with sem:
            return await _probe(client, m)
    results = await asyncio.gather(*(_bounded(m) for m in CANDIDATE_METHODS))

    registered = [m for m in results if m and m[2]]
    # Subtract the methods that should ALWAYS be visible (the WP-core control set)
    builtin = {"system.listMethods", "system.methodHelp"}
    extra = [m for m in registered if m[0] not in builtin]

    if not extra:
        findings.append(Finding(
            severity="info",
            title="XML-RPC method brute-force — no hidden methods found",
            evidence=(f"Probed {len(CANDIDATE_METHODS)} candidate method names; only the "
                       f"WP-core baseline ({len(registered)} method(s)) responded as registered."),
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    findings.append(Finding(
        severity="medium",
        title=f"XML-RPC: {len(extra)} hidden method(s) registered",
        evidence="\n".join(f"  - {m} (HTTP {s})" for m, s, _r in extra) + (
            "\n\nThese methods don't appear in `system.listMethods` but accept XML-RPC calls. "
            "If any are exec-style (`debug.eval`, `internal.shell`, `updraftplus.dumpConfig`), "
            "they're worth deeper manual review with appropriate parameters."
        ),
        remediation=(
            "1. If you don't use XML-RPC at all, disable it: nginx `location = /xmlrpc.php "
            "{ deny all; }` (also blocks Jetpack — review trade-off).\n"
            "2. If you need Jetpack but nothing else, use a plugin like 'Disable XML-RPC "
            "Pingback' or `add_filter('xmlrpc_methods', function($m){ unset($m['internal.X']); "
            "return $m; })` to whitelist only the methods you genuinely need."
        ),
        url=client.url("/xmlrpc.php"),
    ))
    return findings
