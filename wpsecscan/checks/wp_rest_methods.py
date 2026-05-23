"""WP REST API method enumeration via OPTIONS.

For each REST namespace discovered by rest_api, send OPTIONS and look at the
Allow header. Plugins that register POST/PUT/DELETE endpoints sometimes forget
to gate them behind capability checks.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

NAMESPACES_TO_OPTIONS = (
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/comments",
    "/wp-json/wp/v2/media",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/settings",
    "/wp-json/wp/v2/themes",
    "/wp-json/wp/v2/plugins",
    "/wp-json/wp/v2/block-renderer",
    "/wp-json/wc/v3/products",
    "/wp-json/wc/v3/customers",
    "/wp-json/wc/v3/orders",
    "/wp-json/contact-form-7/v1/contact-forms",
    "/wp-json/wpforms/v1/forms",
    "/wp-json/jetpack/v4/options",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    flagged: list[dict] = []
    for path in NAMESPACES_TO_OPTIONS:
        step(f"OPTIONS {path}...")
        r = await client.request("OPTIONS", path)
        if r is None or r.status_code not in (200, 204):
            continue
        allow = r.headers.get("allow", "") or r.headers.get("Allow", "")
        if not allow:
            continue
        methods = [m.strip().upper() for m in allow.split(",")]
        write_methods = [m for m in methods if m in ("POST", "PUT", "PATCH", "DELETE")]
        if write_methods:
            flagged.append({
                "path": path,
                "allow": allow,
                "write_methods": write_methods,
            })

    if not flagged:
        findings.append(
            Finding(
                severity="info",
                title="No REST namespaces advertise write methods unauthenticated",
                evidence=f"OPTIONS sent to {len(NAMESPACES_TO_OPTIONS)} known REST paths; none returned write-method Allow headers.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    for f in flagged:
        # POST on /wp-json/wp/v2/posts is normal for authenticated users — but Allow
        # alone doesn't reveal whether the server actually permits anonymous writes.
        # We surface it as low severity so the user can verify.
        sev = "medium" if any(m in ("PUT", "DELETE", "PATCH") for m in f["write_methods"]) else "low"
        findings.append(
            Finding(
                severity=sev,
                title=f"REST {f['path']} allows write methods: {', '.join(f['write_methods'])}",
                evidence=(
                    f"OPTIONS {f['path']} -> 200 with `Allow: {f['allow']}`.\n\n"
                    "OPTIONS reflects every method the plugin registered, regardless of authn requirement. "
                    "Verify each write method actually rejects anonymous clients by sending one POST/PUT/DELETE."
                ),
                remediation=(
                    "Audit the plugin's REST registration. Every write method should have "
                    "`'permission_callback' => function($req){ return current_user_can('...'); }` set."
                ),
                url=client.url(f["path"]),
            )
        )
    return findings
