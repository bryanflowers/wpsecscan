"""`/wp-json/wp/v2/users/me` unauthenticated capability leak.

An unauthenticated GET to /wp-json/wp/v2/users/me should return 401. If
it returns 200 with a `capabilities` map, the site has lost track of
authentication and is leaking the capability list (administrator,
editor, contributor, etc.) of whoever's WP-related cookies happen to be
on the connection. This is distinct from the author-slug leak the
`users` check probes for — it's a structural auth bypass.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("probing /wp-json/wp/v2/users/me unauthenticated...")
    r = await client.get("/wp-json/wp/v2/users/me")
    if r is None:
        return findings
    if r.status_code != 200:
        findings.append(Finding(
            severity="info",
            title=f"/wp-json/wp/v2/users/me returns {r.status_code} unauthenticated (good)",
            evidence=f"Anonymous request → HTTP {r.status_code}.",
            remediation="No action — REST is correctly requiring authentication for /users/me.",
            url=client.url("/wp-json/wp/v2/users/me"),
        ))
        return findings
    try:
        data = r.json()
    except ValueError:
        return findings
    if not isinstance(data, dict):
        return findings
    caps = data.get("capabilities") or {}
    role = data.get("roles") or []
    name = data.get("name") or data.get("slug") or "(unknown)"
    if caps or role:
        sev = "critical" if any(
            r in str(role).lower() for r in ("administrator", "admin", "super_admin")
        ) else "high"
        findings.append(Finding(
            severity=sev,
            title=f"REST /wp-json/wp/v2/users/me returns capabilities unauthenticated (role: {','.join(role) if role else '?'})",
            evidence=(
                f"Anonymous GET /wp-json/wp/v2/users/me → HTTP 200\n"
                f"  User: {name}\n"
                f"  Roles: {role}\n"
                f"  Capabilities present: {len(caps)} entries\n\n"
                "This indicates the REST API has lost track of authentication state, "
                "or a plugin has overridden the route to bypass `current_user_can()`. "
                "An attacker now knows which actions an unauthenticated client can "
                "perform before even attempting privilege escalation."
            ),
            remediation=(
                "Verify which plugin or theme exposed /users/me without auth. "
                "Standard WordPress requires `edit_users` capability for this route — "
                "if it's returning 200 anonymously, something has hooked "
                "`rest_endpoints` or registered a public override. Audit any custom "
                "`register_rest_route` calls in your active plugins."
            ),
            url=client.url("/wp-json/wp/v2/users/me"),
            extra={"roles": role, "capability_count": len(caps)},
        ))
    return findings
