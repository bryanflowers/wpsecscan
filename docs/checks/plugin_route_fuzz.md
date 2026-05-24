# Plugin REST-route fuzzer

**check_id**: `plugin_route_fuzz`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-RAC

## What it does

H9 Plugin-route fuzzer.

Extends the existing plugin enumeration: for every detected plugin slug,
probe its known unauthenticated REST endpoints (sourced from a curated
mapping). Catches the long tail of "this plugin exposes /wp-json/foo/v1/
without an auth check" — about 30% of WordPress sites run at least one.

We're conservative: only GET probes (no writes), only `info` severity for
"endpoint accessible" findings; the severity bumps to `medium`/`high` if
the response body matches a known data-leak signature.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only plugin_route_fuzz
```
