"""Detect internal hostnames / staging IDs in REST namespace strings.

Each WordPress plugin registers REST routes via `register_rest_route()`
with a chosen namespace. The full namespace list is published at
/wp-json/. Some plugins/teams embed environment names or internal service
identifiers in namespace strings (e.g. `prod-east-1/v1`,
`staging-api/v2`, `my-internal-service/v1`) — leaks topology info.
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


_SUSPECT_TOKENS = (
    "staging", "stage", "-dev", "_dev", ".dev",
    "internal", "intranet", "prod-",
    "-east-", "-west-", "-eu-", "-us-",
    "test-", "-test",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("inspecting /wp-json/ namespaces for internal/staging tokens...")
    r = await client.get("/wp-json/")
    if r is None or r.status_code != 200:
        return findings
    try:
        data = r.json()
    except ValueError:
        return findings
    if not isinstance(data, dict):
        return findings
    namespaces = data.get("namespaces") or []
    if not isinstance(namespaces, list):
        return findings
    suspect = [n for n in namespaces if isinstance(n, str)
               and any(tok in n.lower() for tok in _SUSPECT_TOKENS)]
    if not suspect:
        return findings
    lines = "\n".join(f"  - {n}" for n in suspect)
    findings.append(Finding(
        severity="low",
        title=f"REST namespace(s) leak internal/staging identifiers ({len(suspect)})",
        evidence=(
            f"/wp-json/ namespaces contain internal-shaped tokens:\n{lines}\n\n"
            "These come directly from plugin `register_rest_route()` calls and "
            "sometimes embed CI/CD artifact names, environment identifiers, or "
            "internal service names that should not be public."
        ),
        remediation=(
            "Audit which plugin registered each namespace and check whether the "
            "internal name is intentional. If a staging-only plugin shipped to "
            "production, deactivate it. If the namespace is legitimate but "
            "leaks topology, rename it in the plugin source."
        ),
        url=client.url("/wp-json/"),
        extra={"suspect_namespaces": suspect},
    ))
    return findings
