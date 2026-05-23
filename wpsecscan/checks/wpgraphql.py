"""WPGraphQL endpoint audit.

The WPGraphQL plugin ships its own attack surface independent of the REST API.
Common misconfigurations:
  - Introspection enabled in production (any attacker can map the full schema)
  - Unauthenticated user enumeration via the `users` root query
  - Mutations accessible without auth (rare but catastrophic)
  - Batch queries enabled → DoS amplification
"""
from __future__ import annotations

import json

from ..http import Client
from ..models import Finding

# Known WPGraphQL endpoints. /graphql is the default; the rest are fallbacks
# / common rewrites.
ENDPOINTS = (
    "/graphql",
    "/index.php?graphql",
    "/wp-json/graphql/v1/graphql",
)

# Minimal introspection query — exposes schema if introspection is on
INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'

# Unauthenticated user listing — should require nodes auth in hardened installs
USERS_QUERY = '{"query":"{users(first:50){nodes{name slug email}}}"}'

# Unauth mutation attempt — never write-side: we send an obviously-invalid input
# and only look at whether the server accepts the mutation at all (not whether
# it succeeds). This stays read-only.
MUTATION_PROBE = '{"query":"mutation{registerUser(input:{username:\\"wpsx-canary\\"}){user{id}}}"}'


async def _post_json(client: Client, path: str, body: str):
    return await client.post(path, content=body, headers={"Content-Type": "application/json"})


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    live_endpoint: str | None = None
    for path in ENDPOINTS:
        step(f"probing {path} for WPGraphQL...")
        r = await _post_json(client, path, '{"query":"{__typename}"}')
        if r is None:
            continue
        if r.status_code == 200 and "data" in (r.text or "") and "__typename" in (r.text or ""):
            live_endpoint = path
            break
        # Some installs return 400 for invalid GET but accept POST — already POSTing here

    if not live_endpoint:
        findings.append(
            Finding(
                severity="info",
                title="WPGraphQL endpoint not detected",
                evidence=f"Probed {len(ENDPOINTS)} known WPGraphQL paths. None responded with a GraphQL data envelope.",
                remediation="No action needed (WPGraphQL is not in use, or it's mounted at a custom path).",
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="info",
            title=f"WPGraphQL endpoint live at {live_endpoint}",
            evidence=f"POST {live_endpoint} with `{{__typename}}` returned a GraphQL response envelope.",
            remediation="No action needed by itself — see follow-up findings for any misconfigurations.",
            url=client.url(live_endpoint),
        )
    )

    # 1. Introspection
    step("testing WPGraphQL introspection...")
    r = await _post_json(client, live_endpoint, INTROSPECTION_QUERY)
    if r is not None and r.status_code == 200:
        body = r.text or ""
        if "__schema" in body and '"types"' in body:
            findings.append(
                Finding(
                    severity="medium",
                    title="WPGraphQL introspection is enabled",
                    evidence=(
                        f"POST {live_endpoint} with `{{__schema{{types{{name}}}}}}` returned the full schema.\n"
                        "Attackers can use introspection to map every query, mutation, and custom type — saves them "
                        "hours of recon."
                    ),
                    remediation=(
                        "In WPGraphQL → Settings, set 'Public Introspection Enabled' to OFF for production. "
                        "Or in code: add_filter('graphql_introspection_enabled', '__return_false');"
                    ),
                    url=client.url(live_endpoint),
                )
            )

    # 2. User enumeration via users query
    step("testing unauthenticated WPGraphQL user listing...")
    r = await _post_json(client, live_endpoint, USERS_QUERY)
    if r is not None and r.status_code == 200:
        body = r.text or ""
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            data = {}
        nodes = (data.get("data", {}) or {}).get("users", {}) or {}
        if isinstance(nodes, dict):
            user_list = nodes.get("nodes") or []
            if isinstance(user_list, list) and user_list:
                emails_present = any(u.get("email") for u in user_list if isinstance(u, dict))
                # Emails would be a serious leak — the WPGraphQL default hides them but some plugins re-expose
                sev = "high" if emails_present else "medium"
                names = [u.get("name") or u.get("slug") for u in user_list if isinstance(u, dict)]
                findings.append(
                    Finding(
                        severity=sev,
                        title=f"WPGraphQL discloses {len(user_list)} user(s) unauthenticated" + (" with EMAIL" if emails_present else ""),
                        evidence=(
                            f"POST {live_endpoint} with `{{users{{nodes{{name slug email}}}}}}` returned {len(user_list)} record(s).\n"
                            f"Sample: {', '.join(str(n) for n in names[:10] if n)}"
                            + ("\nEmail addresses are present — phishing-ready dataset." if emails_present else "")
                        ),
                        remediation=(
                            "Restrict the users root field to authenticated requests:\n"
                            "  add_filter('graphql_user_query_args', function($args, $source, $input, $context, $info){\n"
                            "    if (!is_user_logged_in()) throw new \\GraphQL\\Error\\UserError('auth required');\n"
                            "    return $args;\n"
                            "  }, 10, 5);"
                        ),
                        url=client.url(live_endpoint),
                    )
                )

    # 3. Unauth mutation
    step("testing unauthenticated WPGraphQL mutation...")
    r = await _post_json(client, live_endpoint, MUTATION_PROBE)
    if r is not None and r.status_code == 200:
        body = (r.text or "").lower()
        # If the response mentions our canary OR returns a user id, the mutation was accepted at the layer
        if "wpsx-canary" in body or '"id"' in body:
            findings.append(
                Finding(
                    severity="high",
                    title="WPGraphQL accepts mutations from unauthenticated clients",
                    evidence=(
                        f"POST {live_endpoint} with a registerUser mutation was processed (no auth error). "
                        "The mutation may have been validated and rejected on application logic, but the gate isn't auth."
                    ),
                    remediation=(
                        "Wrap mutations behind capability checks. For registerUser specifically, follow "
                        "WPGraphQL's auth recipes: https://www.wpgraphql.com/docs/authentication-and-authorization "
                        "Disable specific mutations via the graphql_register_types filter."
                    ),
                    url=client.url(live_endpoint),
                )
            )

    # 4. Batch query DoS amplification
    step("testing WPGraphQL batch query amplification...")
    batch_body = "[" + ",".join([INTROSPECTION_QUERY] * 20) + "]"
    r = await _post_json(client, live_endpoint, batch_body)
    if r is not None and r.status_code == 200:
        body = r.text or ""
        # If the server returns a list of 20 results, batching is enabled
        if body.lstrip().startswith("[") and body.count("__schema") >= 5:
            findings.append(
                Finding(
                    severity="medium",
                    title="WPGraphQL accepts batched queries (DoS amplification vector)",
                    evidence=(
                        f"POST {live_endpoint} with a 20-query JSON array returned a list response. "
                        "Attackers can amplify a single HTTP request into many DB queries."
                    ),
                    remediation=(
                        "Update WPGraphQL to the latest version (recent releases cap batch size by default). "
                        "Or disable batching with the graphql_request_data filter."
                    ),
                    url=client.url(live_endpoint),
                )
            )

    return findings
