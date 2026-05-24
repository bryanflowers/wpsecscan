# Headless/API-first WP audit (#87-91)

**check_id**: `headless_wp_audit`
**aggressive**: no
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
wpsecscan --target https://example.com --only headless_wp_audit
```
