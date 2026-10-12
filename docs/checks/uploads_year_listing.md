---
id: uploads_year_listing
title: "/wp-content/uploads/YYYY/ directory listing"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 99
---

# /wp-content/uploads/YYYY/ directory listing

**check_id**: `uploads_year_listing`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Per-year /wp-content/uploads/YYYY/ directory-listing probe.

The existing `directory_listing` check probes the uploads root. But many
shared-hosting `.htaccess` configurations disable autoindex at the
parent dir while leaving each year-subdirectory exposed (the `Options
-Indexes` directive applies per-scope and isn't propagated to children
on some Apache configs). We probe the last three calendar years
explicitly to catch those edge cases.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Per-year uploads directory listing enabled (⟨count⟩ year(s)) | Add `Options -Indexes` to the deepest level needed, or drop an empty `index.html` into each year directory as belt-and-braces. Nginx: ensure `autoindex off` (the default) and verify no location block re-enables it for /wp-content/uploads/. |

## Evidence the check records

- Per-year uploads directory listing enabled (⟨count⟩ year(s)): Year-subdirectory autoindex is returning a real Apache/Nginx directory listing: ⟨lines⟩ Sometimes a parent rule (Options -Indexes) doesn't propagate to year subdirectories, especially on cPanel shared hosting. Visitors can now enumerate every uploaded file by year.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.10
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: AC.L2-3.1.4
- **compliance_v2 / nist_csf**: PR.DS-05
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan only uploads_year_listing https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
