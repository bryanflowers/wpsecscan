# Source-map exposure

**check_id**: `source_maps`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials in Files

## What it does

Source-map exposure check.

Scans response bodies for `//# sourceMappingURL=...` comments and probes the
referenced `.map` files. A served .map exposes the full pre-minified JS source
(including bundled credentials, internal API paths, debug logging).

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 10.g
- **compliance_v2 / cmmc**: SI.L1-3.14.1
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 4.1
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only source_maps
```
