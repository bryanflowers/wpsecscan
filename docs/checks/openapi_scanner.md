---
id: openapi_scanner
title: "OpenAPI / Swagger endpoint scanner (#26)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 136
---

# OpenAPI / Swagger endpoint scanner (#26)

**check_id**: `openapi_scanner`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

#26 (from ZAP) — OpenAPI / Swagger endpoint scanner.

Auto-discovers an OpenAPI v2 / v3 / Swagger spec at common paths, then
probes every documented endpoint with the most-permissive HTTP method
to surface:

  - Endpoints that respond 200 OK without authentication
  - Endpoints that disclose data (`/users`, `/admin/*`)
  - Endpoints that accept input shapes the spec doesn't validate (sent
    a junk body, looked for `500 Internal Server Error` vs `400 Bad
    Request`)

Discovery probes:
  - /openapi.json, /openapi.yaml
  - /swagger.json, /swagger.yaml
  - /swagger/v1/swagger.json (ASP.NET)
  - /api-docs, /api-docs.json
  - /v2/api-docs, /v3/api-docs (springdoc default)
  - /wp-json/ (WP REST root — already in its own check, but we include it
    for completeness)

## Request footprint

The module contains 2 request call(s) to the target (GET x1, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ OpenAPI endpoint(s) reachable unauth | Verify each endpoint genuinely intends to be public. Endpoints that mention 'admin', 'user', 'config', or 'internal' in their path should require auth. |
| info | OpenAPI spec discovered at ⟨spec_path⟩ (⟨count⟩ endpoint(s)) | If the spec was published unintentionally, move it to an authenticated path. If intentional (public API), make sure no admin / internal endpoint is documented in the public spec. |
| info | OpenAPI/Swagger spec — none discovered | No action. |

## Evidence the check records

- OpenAPI spec discovered at ⟨spec_path⟩ (⟨count⟩ endpoint(s)): Version: ⟨value⟩ First 10 endpoints: ⟨value⟩
- OpenAPI/Swagger spec — none discovered: Probed ⟨count⟩ common spec paths; nothing usable returned.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CA.L2-3.12.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.5
- **compliance_v2 / iso_27001_2022**: A.5.36

## Run only this check

```
wpsecscan only openapi_scanner https://example.com
```

`only` runs this check alone and prints its findings.
