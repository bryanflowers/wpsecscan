---
id: headless_wp_audit
title: "Headless/API-first WP audit (#87-91)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 227
---

# Headless/API-first WP audit (#87-91)

**check_id**: `headless_wp_audit`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-RAC

## What it does

Round-59 #87-91 — Headless / API-first WordPress audit.

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

## Request footprint

The module contains 7 request call(s) to the target (GET x5, POST x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Possible Atlas / WPE purge-token leak in HTML | ROTATE the token in WPE dashboard. Move env var read to server-only path. |
| critical | wp-config.php served as text from /wp-config.php | PHP processing is broken. Re-enable PHP-FPM, or in a Bedrock setup move wp-config.php out of the web root. |
| high | WPGraphQL: 50-alias amplification accepted | Install `wp-graphql-query-depth-limit` or add custom rule limiting query complexity. The alias-amplification pattern turns one HTTP request into N DB queries (DoS multiplier). |
| medium | WPGraphQL introspection enabled in production | Disable introspection in production: in `WPGraphQL > Settings > GraphiQL IDE`, uncheck `Enable Public Introspection`. Or filter `graphql_introspection_enabled` to `__return_false`. |
| low | REST API only reachable via legacy `?rest_route=` (pretty permalinks off) | In Settings &gt; Permalinks, switch to anything other than 'Plain'. This unlocks the pretty REST URL and reduces fingerprint surface. |
| info | Bedrock layout detected (⟨count⟩ markers) | Bedrock keeps wp-config out of the web root — good. Verify `/config/environments/production.php` is 403 from public web. If `/config/application.php` returns 200, your nginx isn't blocking it. |
| info | Gatsby front-end detected (decoupled WordPress) | Confirm `gatsby-source-wordpress` uses an authenticated REST/GraphQL endpoint at build-time, not anonymous. |
| info | Headless WP audit — no issues | No action. |
| info | Next.js front-end detected (decoupled WordPress) | Verify the WP REST endpoint is CORS-locked to the Next.js origin only. Common misconfiguration: WP REST has `Access-Control-Allow-Origin: *` because Next.js calls it. Use a per-route allow-list filter. |
| info | WP Engine Atlas / headless markers detected | If you use Atlas cache-purge tokens, NEVER inline them in `_app.js`. Move to a server-side env var read by `getStaticProps`. |

## Evidence the check records

- WPGraphQL introspection enabled in production: POST ⟨path⟩ returned a schema introspection response (⟨count⟩ bytes).
- Next.js front-end detected (decoupled WordPress): `/_next/` or `__NEXT_DATA__` references found.
- Gatsby front-end detected (decoupled WordPress): Gatsby markers in HTML.
- WP Engine Atlas / headless markers detected: WP Engine/Atlas reference in HTML.
- REST API only reachable via legacy `?rest_route=` (pretty permalinks off): /wp-json/wp/v2/posts 404; /?rest_route=/wp/v2/posts 200.
- wp-config.php served as text from /wp-config.php: GET /wp-config.php -&gt; 200 returning PHP source. Catastrophic creds leak.
- Possible Atlas / WPE purge-token leak in HTML: Match: ...⟨value⟩...
- WPGraphQL: 50-alias amplification accepted: POST ⟨path⟩ {50 aliased posts queries} -&gt; 200 with all aliases resolved.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only headless_wp_audit https://example.com
```

`only` runs this check alone and prints its findings.
