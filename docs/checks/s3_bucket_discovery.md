# S3 bucket discovery + public-ACL

**check_id**: `s3_bucket_discovery`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1530 — Data from Cloud Storage
**CWE**: CWE-732
**D3FEND**: D3-RAC

## What it does

S3 bucket discovery + ACL scan.

Generates likely S3 bucket names from the target's hostname using common
suffixes/prefixes (-backup, -uploads, -media, -static, -assets, -prod, -staging).
For each guessed name, attempts:
  1. `GET https://<bucket>.s3.amazonaws.com/?list-type=2` — public LIST ACL
  2. `HEAD https://<bucket>.s3.amazonaws.com/` — bucket existence

Reports public-readable buckets as high; existing-but-private as info.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only s3_bucket_discovery
```
