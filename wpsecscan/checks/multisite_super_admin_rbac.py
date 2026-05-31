"""F13 (v2.8.1) — Multisite super-admin RBAC bypass probe.

Some multisite-aware plugins (notably User Role Editor pre-4.64,
Members pre-3.2.6) allowed regular admins to grant themselves
super-admin via a REST/AJAX endpoint that omitted the
`is_super_admin()` check. We probe for those endpoints and emit
a low-severity advisory if found (full exploitation requires
auth, which we don't have).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_SUSPECT_PATHS = (
    "/wp-json/user-role-editor/v1/roles",
    "/wp-json/members/v1/roles",
    "/wp-admin/admin-ajax.php?action=ure_ajax",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F13: probing role-editor REST endpoints")
    findings: list[Finding] = []
    for p in _SUSPECT_PATHS:
        r = await client.get(p)
        if r is not None and r.status_code in (200, 401, 403):
            findings.append(Finding(severity="low",
                                      title=f"F13: role-editor plugin endpoint exposed at {p}",
                                      evidence=f"GET {p} → {r.status_code}",
                                      remediation=(
                                          "Update User Role Editor >= 4.64 and Members "
                                          ">= 3.2.6. Audit any custom role-editor plugins "
                                          "for missing `is_super_admin()` guards on "
                                          "role-modification endpoints."),
                                      url=ctx["target"]))
    return findings
