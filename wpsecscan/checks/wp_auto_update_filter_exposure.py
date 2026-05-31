"""F7 (v2.8.1) — WP auto-update filter exposure probe.

WordPress exposes the auto-update state per-plugin via
`/wp-json/wp/v2/plugins?_fields=auto_update`. If that endpoint is
publicly listable without auth, attackers learn which plugins are
NOT on auto-update and prioritise CVE exploitation for those.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F7: probing public auto-update state exposure")
    r = await client.get("/wp-json/wp/v2/plugins?_fields=plugin,auto_update")
    if r is None or r.status_code != 200:
        return []
    try:
        data = r.json()
    except ValueError:
        return []
    if not isinstance(data, list) or not data:
        return []
    no_auto = [p.get("plugin", "?") for p in data
               if isinstance(p, dict) and not p.get("auto_update")]
    if no_auto:
        return [Finding(severity="medium",
                         title=f"F7: {len(no_auto)} plugin(s) have auto-update OFF and the state is publicly listable",
                         evidence=(
                             f"Public REST plugins list returned {len(data)} plugins; "
                             f"{len(no_auto)} have auto_update=false. Example: {no_auto[:5]}.\n"
                             "Combined with public version disclosure, attackers can "
                             "prioritise CVE exploitation against the stale ones."),
                         remediation=(
                             "Require auth for /wp-json/wp/v2/plugins (`disable_listing` "
                             "filter on `rest_endpoints`). Either turn auto-update ON "
                             "for the listed plugins, or block public REST plugin "
                             "listing entirely."),
                         url=ctx["target"])]
    return []
