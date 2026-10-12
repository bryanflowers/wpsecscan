---
id: rest_fields_dos
title: "REST _fields=* DoS amplification probe"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 139
---

# REST _fields=* DoS amplification probe

**check_id**: `rest_fields_dos`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Endpoint DoS: Service Exhaustion

## What it does

REST API response-size DoS amplification probe.

WordPress's REST API supports `?_fields=*` which expands every field on
every returned resource. On plugin-heavy sites (especially WooCommerce)
this can produce uncompressed responses of several MB from a single
request — a cheap amplification vector for bandwidth-bill DoS.

Passive measurement: one GET with `Accept-Encoding: identity` (no gzip)
to /wp-json/?_fields=* and check the response size against a 500 KB
threshold.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | REST root with _fields=* is ⟨value⟩ KB — DoS amplification vector | Rate-limit /wp-json/ at the WAF or reverse proxy. Cloudflare: add a rule limiting /wp-json/* to ~5 req/sec per IP. Nginx: `limit_req zone=rest burst=10` on `location /wp-json/`. Also consider rejecting _fields=* explicitly via a filter: it's an admin convenience, not a public-API contract. |
| info | REST root with _fields=* is ⟨value⟩ KB (within threshold) | No action. |

## Evidence the check records

- REST root with _fields=* is ⟨value⟩ KB — DoS amplification vector: GET /wp-json/?_fields=* (no compression) → ⟨size⟩ bytes. An attacker who can make repeated requests against this URL can saturate bandwidth quickly: one short request → hundreds of KB out, amplification ratio in the hundreds-to-thousands range. CDNs often don't cache `?_fields=*` (different query strings → different keys).
- REST root with _fields=* is ⟨value⟩ KB (within threshold): GET /wp-json/?_fields=* → ⟨size⟩ bytes (uncompressed).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: SC.L2-3.13.4
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 12.1
- **compliance_v2 / iso_27001_2022**: A.8.6

## Run only this check

```
wpsecscan only rest_fields_dos https://example.com
```

`only` runs this check alone and prints its findings.
