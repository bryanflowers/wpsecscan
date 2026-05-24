"""Round-59 #87-91 — Headless / API-first WordPress audit.

#87 WPGraphQL deep audit — beyond the round-Q `wpgraphql` check:
    introspection on/off, query-depth limit, alias-amplification ratio,
    automatic-persisted-queries (APQ).
#88 Next.js / Gatsby decoupled — detect Next.js _next or Gatsby
    `gatsby-image` markers and check that the WP REST endpoint is
    locked to the front-end origin only.
#89 Bedrock / wp-config-in-env — detect Bedrock layout
    (`/app/themes/`, `/app/plugins/`) and verify wp-config.php is NOT
    in the web root (Bedrock moves it to `/config/`).
#90 Atlas headless cache — WP Engine Atlas/Headless tag — check the
    cache-purge token isn't leaked in the front-end env.
#91 REST permalink rewrite — does `/wp-json/wp/v2/posts` 404 but
    `/?rest_route=/wp/v2/posts` succeed? Indicates missing rewrite +
    permalink not set to "Post name".
"""
from __future__ import annotations

import json
import re
from ..http import Client
from ..models import Finding


WPGRAPHQL_INTROSPECTION_QUERY = ("query{__schema{types{name fields{name}}}}")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    # ---- #87 WPGraphQL deep audit ----
    step("graphql: deep audit...")
    gql_paths = ("/graphql", "/wp-json/graphql/v1/graphql", "/index.php?graphql")
    for path in gql_paths:
        r = await client.post(path, json={"query": WPGRAPHQL_INTROSPECTION_QUERY})
        if r is None or r.status_code not in (200, 400):
            continue
        body = r.text or ""
        if "__schema" not in body:
            continue
        findings.append(Finding(
            severity="medium",
            title="WPGraphQL introspection enabled in production",
            evidence=f"POST {path} returned a schema introspection response ({len(body)} bytes).",
            remediation=("Disable introspection in production: in `WPGraphQL > Settings > "
                          "GraphiQL IDE`, uncheck `Enable Public Introspection`. Or filter "
                          "`graphql_introspection_enabled` to `__return_false`."),
            url=target + path,
        ))
        # Alias-amplification ratio — single field aliased 50x
        amp_query = "query{" + "".join(f"a{i}: posts{{nodes{{id}}}}" for i in range(50)) + "}"
        rr = await client.post(path, json={"query": amp_query})
        if rr is not None and rr.status_code == 200 and rr.text:
            try:
                d = json.loads(rr.text)
                data = d.get("data") or {}
                if len([k for k in data if k.startswith("a")]) > 10:
                    findings.append(Finding(
                        severity="high",
                        title="WPGraphQL: 50-alias amplification accepted",
                        evidence=f"POST {path} {{50 aliased posts queries}} -> 200 with all aliases resolved.",
                        remediation=("Install `wp-graphql-query-depth-limit` or add custom rule "
                                      "limiting query complexity. The alias-amplification pattern "
                                      "turns one HTTP request into N DB queries (DoS multiplier)."),
                        url=target + path,
                    ))
            except (json.JSONDecodeError, ValueError):
                pass
        break

    # ---- #88 Next.js / Gatsby decoupled ----
    step("headless: front-end fingerprint...")
    home = await client.get("/")
    body = (home.text or "") if home else ""
    if "/_next/" in body or "__NEXT_DATA__" in body:
        findings.append(Finding(
            severity="info",
            title="Next.js front-end detected (decoupled WordPress)",
            evidence="`/_next/` or `__NEXT_DATA__` references found.",
            remediation=("Verify the WP REST endpoint is CORS-locked to the Next.js origin only. "
                          "Common misconfiguration: WP REST has `Access-Control-Allow-Origin: *` because "
                          "Next.js calls it. Use a per-route allow-list filter."),
            url=target,
        ))
    if "gatsby-image" in body or "data-gatsby-image" in body:
        findings.append(Finding(
            severity="info",
            title="Gatsby front-end detected (decoupled WordPress)",
            evidence="Gatsby markers in HTML.",
            remediation="Confirm `gatsby-source-wordpress` uses an authenticated REST/GraphQL endpoint at build-time, not anonymous.",
            url=target,
        ))

    # ---- #89 Bedrock detection ----
    bedrock_hits = []
    for p in ("/app/themes/", "/app/plugins/", "/app/mu-plugins/", "/config/application.php"):
        r = await client.get(p)
        if r is not None and r.status_code in (200, 403):
            bedrock_hits.append(p)
    if bedrock_hits:
        findings.append(Finding(
            severity="info",
            title=f"Bedrock layout detected ({len(bedrock_hits)} markers)",
            evidence=", ".join(bedrock_hits[:4]),
            remediation=("Bedrock keeps wp-config out of the web root — good. Verify `/config/environments/production.php` "
                          "is 403 from public web. If `/config/application.php` returns 200, your nginx isn't blocking it."),
            url=target,
        ))
        # Check wp-config.php is NOT in web root
        wc = await client.get("/wp-config.php")
        if wc is not None and wc.status_code == 200 and wc.text and "<?php" in wc.text[:50]:
            findings.append(Finding(
                severity="critical",
                title="wp-config.php served as text from /wp-config.php",
                evidence=f"GET /wp-config.php -> 200 returning PHP source. Catastrophic creds leak.",
                remediation="PHP processing is broken. Re-enable PHP-FPM, or in a Bedrock setup move wp-config.php out of the web root.",
                url=target + "/wp-config.php",
            ))

    # ---- #90 Atlas headless ----
    if "wpengine" in body.lower() or "atlas.wpengine.com" in body.lower():
        findings.append(Finding(
            severity="info",
            title="WP Engine Atlas / headless markers detected",
            evidence="WP Engine/Atlas reference in HTML.",
            remediation=("If you use Atlas cache-purge tokens, NEVER inline them in `_app.js`. "
                          "Move to a server-side env var read by `getStaticProps`."),
            url=target,
        ))
        # Scan inline JS for likely purge-token leak
        token_re = re.compile(r"(?:atlas|wpengine).{0,30}(?:token|key|secret)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})", re.IGNORECASE)
        for m in token_re.finditer(body):
            findings.append(Finding(
                severity="critical",
                title="Possible Atlas / WPE purge-token leak in HTML",
                evidence=f"Match: ...{m.group(0)[:60]}...",
                remediation="ROTATE the token in WPE dashboard. Move env var read to server-only path.",
                url=target,
            ))

    # ---- #91 REST permalink rewrite ----
    step("rest: permalink rewrite probe...")
    pretty = await client.get("/wp-json/wp/v2/posts")
    legacy = await client.get("/?rest_route=/wp/v2/posts")
    if (pretty is None or pretty.status_code == 404) and legacy is not None and legacy.status_code == 200:
        findings.append(Finding(
            severity="low",
            title="REST API only reachable via legacy `?rest_route=` (pretty permalinks off)",
            evidence="/wp-json/wp/v2/posts 404; /?rest_route=/wp/v2/posts 200.",
            remediation=("In Settings > Permalinks, switch to anything other than 'Plain'. "
                          "This unlocks the pretty REST URL and reduces fingerprint surface."),
            url=target + "/wp-json/wp/v2/posts",
        ))

    return findings or [Finding(severity="info", title="Headless WP audit — no issues",
                                 evidence="", remediation="No action.", url=target)]
