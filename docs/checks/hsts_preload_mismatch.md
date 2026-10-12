---
id: hsts_preload_mismatch
title: "HSTS preload list vs header mismatch (A30)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 152
---

# HSTS preload list vs header mismatch (A30)

**check_id**: `hsts_preload_mismatch`
**aggressive**: no
**category**: Transport & headers
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle
**CWE**: CWE-319
**D3FEND**: D3-CRO

## What it does

A30 (v2.6.0) — HSTS preload-list status mismatch.

A site claims `preload` in its Strict-Transport-Security header but
isn't on the actual Chrome preload list (or vice-versa). The mismatch
matters because:

  • `preload` in the header without listing = false sense of security
    (browsers won't preload until submission is accepted).
  • Listed without the header = removal is hard (operators sometimes
    forget they submitted years ago).

We use the freely-mirrored hstspreload.org JSON API.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Apex is on HSTS preload list but header dropped the 'preload' directive | Either re-add 'preload' to the HSTS header, or submit a removal at https://hstspreload.org/removal/?domain=⟨apex⟩ and wait ~12 months for the next Chrome list update. |
| low | HSTS header claims preload but apex isn't on the Chrome preload list | Submit at https://hstspreload.org/?domain=⟨apex⟩ after verifying the eligibility criteria (max-age &gt;= 31536000, includeSubDomains, preload directive — which you have). |

## Evidence the check records

- HSTS header claims preload but apex isn't on the Chrome preload list: HSTS header: ⟨hsts⟩ hstspreload.org status for ⟨apex⟩: not listed. Browsers don't preload until the site is accepted into the list — your header advertises a guarantee you don't yet have.
- Apex is on HSTS preload list but header dropped the 'preload' directive: HSTS header: ⟨hsts⟩ hstspreload.org status for ⟨apex⟩: listed. Removing the header doesn't remove the apex from the preload list; you must submit a removal request.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24

## References

- https://hstspreload.org/api/v2/status?domain=
- https://hstspreload.org/?domain=
- https://hstspreload.org/removal/?domain=

## Run only this check

```
wpsecscan only hsts_preload_mismatch https://example.com
```

`only` runs this check alone and prints its findings.
