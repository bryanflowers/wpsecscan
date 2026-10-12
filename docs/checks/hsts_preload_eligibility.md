---
id: hsts_preload_eligibility
title: "HSTS preload eligibility audit"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 134
---

# HSTS preload eligibility audit

**check_id**: `hsts_preload_eligibility`
**aggressive**: no
**category**: Transport & headers
**max severity**: low
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

HSTS preload eligibility audit.

For inclusion in the Chrome preload list (which Firefox/Safari also use),
the HSTS header must have:
  - max-age &gt;= 31536000 (1 year)
  - includeSubDomains directive present
  - preload directive present
  - the apex domain must be served over HTTPS

Existing tls_headers.py just checks that HSTS exists. This audits the
three preload conditions and additionally hits hstspreload.org's status
API to confirm whether the domain is already on the list.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | HSTS preload eligible but not yet submitted | Submit ⟨domain⟩ at https://hstspreload.org/?domain=⟨domain⟩. Inclusion is reviewed by the Chrome team and propagates with the next browser release. Once preloaded, the browser refuses HTTP for this domain even on first visit — defends against first-load SSL-strip attacks. |
| info | HSTS not preload-eligible — fix to qualify for the preload list | Update the HSTS header to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload Verify all subdomains are HTTPS-only first — preload is a one-way door for the apex domain. Submit at hstspreload.org/?domain=⟨domain⟩ once eligible. |
| info | ⟨domain⟩ is on the Chrome HSTS preload list | No action. |

## Evidence the check records

- HSTS not preload-eligible — fix to qualify for the preload list: Missing preload conditions: ⟨value⟩. Current header: ⟨value⟩
- ⟨domain⟩ is on the Chrome HSTS preload list: hstspreload.org/api/v2/status reports: preloaded. Header: ⟨value⟩
- HSTS preload eligible but not yet submitted: HSTS header satisfies all three preload conditions: max-age = ⟨max_age⟩ (&gt;= 31536000 ✓) includeSubDomains ✓ preload directive ✓ hstspreload.org status: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 09.s
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- https://hstspreload.org/api/v2/status?domain=
- https://hstspreload.org/?domain=

## Run only this check

```
wpsecscan only hsts_preload_eligibility https://example.com
```

`only` runs this check alone and prints its findings.
