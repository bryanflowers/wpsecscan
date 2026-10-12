---
id: rest_link_header
title: "Link: header leaks internal URLs"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 136
---

# Link: header leaks internal URLs

**check_id**: `rest_link_header`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information

## What it does

Audit the `Link:` response header for internal URLs.

The `Link:` header on a WordPress front-page typically contains:
  - rel="https://api.w.org/" pointing at the REST API base
  - rel="next" / rel="prev" pointing at adjacent pages
  - rel="shortlink" / rel="canonical"

Reverse-proxy misconfigurations can leak internal/staging URLs in these
links (e.g. `https://staging-internal.dev/...` appearing on a production
site because the canonical URL is computed from `$_SERVER['HTTP_HOST']`
before the reverse proxy rewrites it). This check fires when any Link
relation points at a hostname that doesn't match the scan target.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Link: header on / leaks ⟨count⟩ internal-looking URL(s) | Set `WP_HOME` and `WP_SITEURL` to the public URL explicitly in wp-config.php so canonical/REST URLs don't fall back to $_SERVER['HTTP_HOST']. Also audit any plugins that override the Link header generation. |

## Evidence the check records

- Link: header on / leaks ⟨count⟩ internal-looking URL(s): The Link response header points at hostnames containing internal/staging tokens: ⟨lines⟩ This usually means the canonical / API-root URLs are being computed from the un-rewritten internal hostname rather than the public host. It leaks infrastructure topology and may indicate a misconfigured reverse proxy.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-18
- **compliance_map / iso_27001**: A.8.23
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.7
- **compliance_v2 / iso_27001_2022**: A.8.23

## References

- https://api.w.org/
- https://staging-internal.dev/

## Run only this check

```
wpsecscan only rest_link_header https://example.com
```

`only` runs this check alone and prints its findings.
