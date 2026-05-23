"""GraphQL query-aliasing DoS probe.

Sends a small batched query that ALIASES the same field 50 times. If the server
returns a 200 with the full 50-element response (rather than rejecting with a
complexity/depth limit), it's amplifying — an attacker can send one HTTP request
that costs the backend 50x normal CPU.

Only runs if /graphql or /index.php?graphql exists.
"""
from __future__ import annotations

import time

from ..http import Client
from ..models import Finding

ALIAS_COUNT = 50
GRAPHQL_PATHS = ("/graphql", "/index.php?graphql", "/wp-json/wp/v2/graphql")


def _build_aliased_query() -> str:
    """Send the same minimal introspection query 50 times under different aliases."""
    aliases = ",\n  ".join(
        f"a{i}: __typename" for i in range(ALIAS_COUNT)
    )
    return "{ " + aliases + " }"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Locate the GraphQL endpoint
    gql_path = None
    for p in GRAPHQL_PATHS:
        step(f"probing GraphQL endpoint {p}...")
        r = await client.post(p, json={"query": "{ __typename }"},
                              headers={"Content-Type": "application/json"})
        if r is not None and r.status_code == 200 and "__typename" in (r.text or ""):
            gql_path = p
            break

    if not gql_path:
        findings.append(
            Finding(
                severity="info",
                title="No GraphQL endpoint detected — alias-DoS probe skipped",
                evidence=f"Probed: {', '.join(GRAPHQL_PATHS)}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Baseline single-field timing
    step(f"baselining {gql_path} single field...")
    t0 = time.perf_counter()
    r = await client.post(gql_path, json={"query": "{ __typename }"},
                          headers={"Content-Type": "application/json"})
    baseline_ms = (time.perf_counter() - t0) * 1000

    # Aliased query
    step(f"sending {ALIAS_COUNT}-aliased query...")
    aliased = _build_aliased_query()
    t1 = time.perf_counter()
    r2 = await client.post(gql_path, json={"query": aliased},
                           headers={"Content-Type": "application/json"})
    aliased_ms = (time.perf_counter() - t1) * 1000

    if r2 is None or r2.status_code >= 400:
        # The server rejected the aliased query — that's the SECURE outcome.
        code = r2.status_code if r2 else "no response"
        findings.append(
            Finding(
                severity="info",
                title=f"GraphQL alias amplification REJECTED at {gql_path}",
                evidence=f"50-aliased query returned HTTP {code} — query-complexity limit appears to be enforced.",
                remediation="No action — your GraphQL endpoint correctly rejects amplification.",
                url=client.url(gql_path),
            )
        )
        return findings

    body = (r2.text or "")
    # If the response carries 50 alias keys, amplification worked.
    alias_hits = body.count('"a')  # crude but reliable for `"a0":, "a1":` etc.
    cost_ratio = aliased_ms / max(baseline_ms, 1.0)

    if alias_hits >= ALIAS_COUNT // 2 and cost_ratio > 2.0:
        findings.append(
            Finding(
                severity="medium",
                title=f"GraphQL alias amplification ACCEPTED at {gql_path}",
                evidence=(
                    f"Single field: {baseline_ms:.0f} ms.  {ALIAS_COUNT}-aliased: {aliased_ms:.0f} ms.\n"
                    f"Cost ratio: {cost_ratio:.1f}x. {alias_hits} aliases reflected in the response.\n"
                    f"An attacker can send 50 identical queries in one HTTP request, amplifying "
                    f"server CPU cost per round-trip."
                ),
                remediation=(
                    "Install a query-complexity / depth-limit middleware. For WPGraphQL: enable "
                    "`graphql_request_data` filter with a max-query-depth limit (most plugins "
                    "default to no limit). Reference: "
                    "https://www.wpgraphql.com/docs/security/#query-depth"
                ),
                url=client.url(gql_path),
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"GraphQL alias amplification not effective at {gql_path}",
                evidence=f"Aliased query cost ratio: {cost_ratio:.1f}x — within tolerance.",
                remediation="No action.",
                url=client.url(gql_path),
            )
        )
    return findings
