# OpenAPI / Swagger endpoint scanner (#26)

**check_id**: `openapi_scanner`
**aggressive**: no
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
wpsecscan --target https://example.com --only openapi_scanner
```
