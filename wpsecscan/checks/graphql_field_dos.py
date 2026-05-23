"""GraphQL query-depth DoS probe.

Sends a deeply-nested introspection query (`{ __schema { types { fields { type
{ fields { ... }}}}}}` × N). If the server returns 200 with the full response,
no depth limit is enforced and an attacker can craft queries that scale
exponentially.

Aggressive-only (sends a moderately expensive query).
"""
from __future__ import annotations

import time

from ..http import Client
from ..models import Finding

DEPTH = 15
GRAPHQL_PATHS = ("/graphql", "/index.php?graphql", "/wp-json/wp/v2/graphql")


def _build_nested_query(depth: int) -> str:
    """Build `{ __schema { types { fields { type { fields { ... }}}}}` to a given depth."""
    inner = "name"
    for _ in range(depth):
        inner = "fields { type { " + inner + " } }"
    return "{ __schema { types { " + inner + " } } }"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="GraphQL depth-DoS probe skipped (requires --aggressive)",
                evidence="This probe sends a moderately expensive introspection query.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Locate GraphQL
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
                title="GraphQL depth-DoS probe skipped — no GraphQL endpoint",
                evidence=f"Probed: {', '.join(GRAPHQL_PATHS)}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"sending depth-{DEPTH} nested query to {gql_path}...")
    q = _build_nested_query(DEPTH)
    t0 = time.perf_counter()
    r = await client.post(gql_path, json={"query": q},
                          headers={"Content-Type": "application/json"})
    elapsed_ms = (time.perf_counter() - t0) * 1000

    if r is None:
        findings.append(
            Finding(
                severity="medium",
                title=f"GraphQL depth-{DEPTH} query exhausted the connection at {gql_path}",
                evidence=f"No response after {elapsed_ms:.0f} ms — server either crashed or hit a default timeout.",
                remediation=(
                    "Install a query-depth-limit middleware. For WPGraphQL: use the "
                    "`graphql_request_data` filter to reject queries deeper than ~10."
                ),
                url=client.url(gql_path),
            )
        )
        return findings

    if r.status_code in (200,):
        findings.append(
            Finding(
                severity="medium",
                title=f"GraphQL accepted a depth-{DEPTH} introspection query at {gql_path}",
                evidence=(
                    f"Server returned 200 after {elapsed_ms:.0f} ms for a depth-{DEPTH} nested query "
                    "(no depth-limit middleware). An attacker can craft deeper queries that scale "
                    "the per-request CPU cost exponentially."
                ),
                remediation=(
                    "Add a depth-limit. WPGraphQL has a built-in `query_depth` filter — set max ~10. "
                    "Or use graphql-armor / graphql-cost-analysis if running custom graphql code."
                ),
                url=client.url(gql_path),
            )
        )
    elif r.status_code >= 400:
        findings.append(
            Finding(
                severity="info",
                title=f"GraphQL depth-{DEPTH} query REJECTED at {gql_path} (good)",
                evidence=f"HTTP {r.status_code} after {elapsed_ms:.0f} ms — depth-limit appears enforced.",
                remediation="No action — depth-limit looks healthy.",
                url=client.url(gql_path),
            )
        )
    return findings
