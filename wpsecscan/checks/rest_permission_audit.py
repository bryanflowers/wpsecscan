"""#3 WP REST `permission_callback` audit.

Fetches /wp-json/ + every namespace's route listing, then probes each
route with GET (no auth). Flags routes that respond 200 (open) when
their `methods` list includes POST/PUT/DELETE (privileged actions
usually need auth). Many plugins omit `permission_callback` or use
`return true` — those routes leak data + accept writes.
"""
from __future__ import annotations

import asyncio
from ..http import Client
from ..models import Finding


async def _fetch_namespaces(client: Client) -> list[str]:
    r = await client.get("/wp-json/")
    if r is None:
        return []
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        return []
    return list(data.get("namespaces") or [])


async def _fetch_routes(client: Client, ns: str) -> dict:
    r = await client.get(f"/wp-json/{ns}")
    if r is None:
        return {}
    try:
        return (r.json() or {}).get("routes") or {}
    except Exception:  # noqa: BLE001
        return {}


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    findings: list[Finding] = []
    step("REST permission audit: listing namespaces...")
    namespaces = await _fetch_namespaces(client)
    if not namespaces:
        return [Finding(severity="info", title="REST permission audit — /wp-json/ inaccessible",
                        evidence="No namespaces returned.", remediation="No action.", url=ctx["target"])]

    # Collect every route from every namespace
    route_map: dict[str, dict] = {}
    for ns in namespaces[:8]:  # cap to avoid request explosion
        step(f"REST: namespace {ns}...")
        routes = await _fetch_routes(client, ns)
        route_map.update(routes)

    # Probe each route — flag routes where any method is POST/PUT/DELETE/PATCH
    # AND the GET returns 200 (suggesting the permission_callback is `__return_true`)
    suspicious: list[tuple[str, list[str], int]] = []
    sem = asyncio.Semaphore(4)
    async def _probe(path: str, methods: list[str]):
        async with sem:
            r = await client.get(path)
            return (path, methods, r.status_code if r else 0)
    privileged_paths = [(p, list(set(m for ep in (info.get("endpoints") or [])
                                       for m in (ep.get("methods") or []))))
                        for p, info in route_map.items()
                        if any(m in ("POST", "PUT", "PATCH", "DELETE")
                                for ep in (info.get("endpoints") or [])
                                for m in (ep.get("methods") or []))]
    results = await asyncio.gather(*(_probe(p, m) for p, m in privileged_paths[:30]))
    for path, methods, status in results:
        if 200 <= status < 300 and any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods):
            suspicious.append((path, methods, status))

    if not suspicious:
        return [Finding(severity="info", title=f"REST permission audit — {len(privileged_paths)} privileged route(s) clean",
                        evidence=f"All privileged routes correctly rejected unauth GET.",
                        remediation="No action.", url=ctx["target"])]
    findings.append(Finding(
        severity="high",
        title=f"REST: {len(suspicious)} privileged route(s) accept unauth GET",
        evidence="\n".join(f"  - {p} (methods: {','.join(m)}) -> {s}" for p, m, s in suspicious[:15]),
        remediation="For each route, add `'permission_callback' => function() { return current_user_can('edit_posts'); }` (or stricter capability) in the plugin's `register_rest_route` call. `__return_true` is never appropriate for write methods.",
        url=ctx["target"] + "/wp-json/",
    ))
    return findings
