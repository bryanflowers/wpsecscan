"""GraphQL DoS probes — alias amplification (always) + depth nesting (aggressive).

Discovers the GraphQL endpoint once, then runs:
  1. Alias amplification — sends the same field aliased 50 times. If the server
     accepts it without rejecting via a complexity/depth limit, an attacker
     can 50x backend CPU per HTTP request.
  2. Depth nesting (aggressive only) — sends a deeply-nested introspection
     query. If accepted, queries can be scaled exponentially.

Only runs when /graphql or /index.php?graphql exists.
"""
from __future__ import annotations

import re
import time

# v2.8.5 M2 — `body.count('"a')` matched any JSON key starting with
# the letter 'a' (e.g. "address", "available"), inflating alias_hits.
# Tight regex matches only the actual aN alias pattern emitted above.
_ALIAS_KEY_RE = re.compile(r'"a\d+"\s*:')

from ..http import Client
from ..models import Finding

ALIAS_COUNT = 50
DEPTH = 15
GRAPHQL_PATHS = ("/graphql", "/index.php?graphql", "/wp-json/wp/v2/graphql")


def _build_aliased_query() -> str:
    aliases = ",\n  ".join(f"a{i}: __typename" for i in range(ALIAS_COUNT))
    return "{ " + aliases + " }"


def _build_nested_query(depth: int) -> str:
    inner = "name"
    for _ in range(depth):
        inner = "fields { type { " + inner + " } }"
    return "{ __schema { types { " + inner + " } } }"


async def _discover(client: Client, step) -> str | None:
    for p in GRAPHQL_PATHS:
        step(f"probing GraphQL endpoint {p}...")
        r = await client.post(p, json={"query": "{ __typename }"},
                              headers={"Content-Type": "application/json"})
        if r is not None and r.status_code == 200 and "__typename" in (r.text or ""):
            return p
    return None


async def _alias_probe(client: Client, ctx: dict, gql_path: str, step) -> list[Finding]:
    findings: list[Finding] = []
    step(f"baselining {gql_path} single field...")
    t0 = time.perf_counter()
    await client.post(gql_path, json={"query": "{ __typename }"},
                      headers={"Content-Type": "application/json"})
    baseline_ms = (time.perf_counter() - t0) * 1000

    step(f"sending {ALIAS_COUNT}-aliased query...")
    aliased = _build_aliased_query()
    t1 = time.perf_counter()
    r2 = await client.post(gql_path, json={"query": aliased},
                           headers={"Content-Type": "application/json"})
    aliased_ms = (time.perf_counter() - t1) * 1000

    if r2 is None or r2.status_code >= 400:
        code = r2.status_code if r2 else "no response"
        findings.append(Finding(
            severity="info",
            title=f"GraphQL alias amplification REJECTED at {gql_path}",
            evidence=f"50-aliased query returned HTTP {code} — query-complexity limit appears to be enforced.",
            remediation="No action — your GraphQL endpoint correctly rejects amplification.",
            url=client.url(gql_path),
        ))
        return findings

    body = r2.text or ""
    alias_hits = len(_ALIAS_KEY_RE.findall(body))
    cost_ratio = aliased_ms / max(baseline_ms, 1.0)

    if alias_hits >= ALIAS_COUNT // 2 and cost_ratio > 2.0:
        findings.append(Finding(
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
                "default to no limit). Reference: https://www.wpgraphql.com/docs/security/#query-depth"
            ),
            url=client.url(gql_path),
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"GraphQL alias amplification not effective at {gql_path}",
            evidence=f"Aliased query cost ratio: {cost_ratio:.1f}x — within tolerance.",
            remediation="No action.",
            url=client.url(gql_path),
        ))
    return findings


async def _depth_probe(client: Client, ctx: dict, gql_path: str, step) -> list[Finding]:
    findings: list[Finding] = []
    step(f"sending depth-{DEPTH} nested query to {gql_path}...")
    q = _build_nested_query(DEPTH)
    t0 = time.perf_counter()
    r = await client.post(gql_path, json={"query": q},
                          headers={"Content-Type": "application/json"})
    elapsed_ms = (time.perf_counter() - t0) * 1000

    if r is None:
        findings.append(Finding(
            severity="medium",
            title=f"GraphQL depth-{DEPTH} query exhausted the connection at {gql_path}",
            evidence=f"No response after {elapsed_ms:.0f} ms — server either crashed or hit a default timeout.",
            remediation=(
                "Install a query-depth-limit middleware. For WPGraphQL: use the "
                "`graphql_request_data` filter to reject queries deeper than ~10."
            ),
            url=client.url(gql_path),
        ))
        return findings

    if r.status_code == 200:
        findings.append(Finding(
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
        ))
    elif r.status_code >= 400:
        findings.append(Finding(
            severity="info",
            title=f"GraphQL depth-{DEPTH} query REJECTED at {gql_path} (good)",
            evidence=f"HTTP {r.status_code} after {elapsed_ms:.0f} ms — depth-limit appears enforced.",
            remediation="No action — depth-limit looks healthy.",
            url=client.url(gql_path),
        ))
    return findings


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    gql_path = await _discover(client, step)
    if not gql_path:
        findings.append(Finding(
            severity="info",
            title="No GraphQL endpoint detected — DoS probes skipped",
            evidence=f"Probed: {', '.join(GRAPHQL_PATHS)}",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Always: alias amplification (passive)
    findings.extend(await _alias_probe(client, ctx, gql_path, step))

    # Aggressive only: depth nesting
    if ctx.get("aggressive"):
        findings.extend(await _depth_probe(client, ctx, gql_path, step))

    return findings
