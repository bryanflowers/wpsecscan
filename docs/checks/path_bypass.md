# Path-normalisation bypass probe

**check_id**: `path_bypass`
**aggressive**: yes
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-22
**D3FEND**: D3-RAC

## What it does

Path-normalisation bypass probe (aggressive).

Tests whether a WAF / front-end ACL can be bypassed via encoded path traversal:
  - `..%2f` (URL-encoded /)
  - `..;/` (Tomcat path-parameter trick)
  - `%5c` (backslash, treated as / by some servers)
  - `..%252f` (double-URL-encoded /)
  - `..%c0%af` (overlong UTF-8 /)

Baseline /wp-admin/ + try each bypass variant. If a bypass returns a DIFFERENT
(non-403) response than the baseline, the ACL is bypassable.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only path_bypass
```
