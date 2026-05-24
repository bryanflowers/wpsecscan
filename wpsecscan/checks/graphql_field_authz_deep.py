"""GraphQL field-level authorization deep probe.

Round-64 #70 — wpgraphql.py already flags introspection-enabled
endpoints. This deep variant goes further: it tries to read specific
sensitive fields without authentication. WPGraphQL exposes `users`,
`mediaItems`, `comments`, `posts.author.email` etc. Many sites lock
top-level introspection but forget to lock individual fields' resolvers.
"""
from __future__ import annotations

import json

from ..http import Client
from ..models import Finding

# Each entry: (query, sensitive-field-name-to-look-for, severity, explanation)
_SENSITIVE_QUERIES = (
    (
        "{ users(first: 5) { nodes { id name email username roles { nodes { name } } } } }",
        "email",
        "high",
        "Reading user emails + roles unauthenticated enables direct admin-targeting",
    ),
    (
        "{ users { nodes { capabilities databaseId username } } }",
        "capabilities",
        "high",
        "Reading user capabilities unauthenticated exposes privilege structure",
    ),
    (
        "{ mediaItems(first: 5, where: { status: PRIVATE }) { nodes { sourceUrl status } } }",
        "sourceUrl",
        "high",
        "Reading PRIVATE media unauthenticated leaks otherwise-protected uploads",
    ),
    (
        "{ comments(first: 5, where: { status: HOLD }) { nodes { authorEmail content } } }",
        "authorEmail",
        "medium",
        "Reading held comments leaks commenter emails + content awaiting moderation",
    ),
    (
        "{ posts(first: 5, where: { status: DRAFT }) { nodes { title author { node { email } } } } }",
        "title",
        "high",
        "Reading DRAFT posts unauthenticated exposes unpublished content",
    ),
)

_ENDPOINTS = ("/graphql", "/wp/graphql", "/index.php?graphql", "/api/graphql")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Find a reachable endpoint first
    endpoint = None
    for ep in _ENDPOINTS:
        r = await client.post(
            ep,
            json={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"},
        )
        if r is None:
            continue
        if r.status_code == 200 and "data" in (r.text or ""):
            endpoint = ep
            break
    if endpoint is None:
        return findings

    for query, sentinel_field, sev, why in _SENSITIVE_QUERIES:
        step(f"probing {sentinel_field} field...")
        r = await client.post(
            endpoint,
            json={"query": query},
            headers={"Content-Type": "application/json"},
        )
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            continue
        # If 'errors' contains an authz message, the field is properly locked
        errors = data.get("errors") if isinstance(data, dict) else None
        if errors:
            # Check first error message — common patterns indicate proper authz
            first = errors[0].get("message", "").lower() if errors else ""
            if any(s in first for s in ("not authorized", "permission", "logged in", "authentication")):
                continue
        # Otherwise check data.{users,mediaItems,comments,posts}.nodes and confirm the field appears
        result_data = data.get("data") if isinstance(data, dict) else None
        if not result_data:
            continue
        # Walk the response looking for the sentinel field with a non-null value
        def _walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == sentinel_field and v not in (None, "", []):
                        return True
                    if _walk(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if _walk(item):
                        return True
            return False

        if _walk(result_data):
            findings.append(
                Finding(
                    severity=sev,
                    title=f"GraphQL: unauthenticated read of sensitive field `{sentinel_field}`",
                    evidence=f"POST {endpoint} returned populated `{sentinel_field}` without authentication.\n  Why: {why}",
                    remediation=(
                        f"Restrict `{sentinel_field}` to authenticated callers in WPGraphQL.\n"
                        "Use `graphql_resolve_field` filter or the `wpgraphql_disable_field` setting to require auth.\n"
                        "Disable introspection in production: add `'show_in_graphql' => false` for sensitive types."
                    ),
                    url=client.url(endpoint),
                    extra={"endpoint": endpoint, "field": sentinel_field},
                )
            )

    return findings
