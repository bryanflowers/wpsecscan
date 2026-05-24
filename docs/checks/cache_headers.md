# Cache-header audit

**check_id**: `cache_headers`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1556 — Modify Authentication Process

## What it does

Cache-header audit.

Look at response headers from a few endpoints to detect:
  - Authenticated content cached publicly (`Cache-Control: public` on logged-in views)
  - Missing `Vary` on cookie-sensitive content
  - Cache-poisoning vectors via unkeyed inputs
  - Stale-while-revalidate / immutable assets pointing at non-versioned paths

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.7
- **compliance_map / nist_800_53**: AC-12
- **compliance_map / iso_27001**: A.8.21

## Run only this check

```
wpsecscan --target https://example.com --only cache_headers
```
