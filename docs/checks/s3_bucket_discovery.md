---
id: s3_bucket_discovery
title: "S3 bucket discovery + public-ACL"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 161
---

# S3 bucket discovery + public-ACL

**check_id**: `s3_bucket_discovery`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | S3 bucket publicly LISTABLE: ⟨name⟩ | AWS Console -&gt; S3 -&gt; the bucket -&gt; Permissions -&gt; Block public access -&gt; enable all four blocks. Verify with `aws s3api get-public-access-block`. |
| low | S3 bucket exists (private list-ACL): ⟨name⟩ | Verify object-level public access is also blocked. AWS Trusted Advisor or `aws s3api list-objects --bucket NAME` (as bucket owner) confirms. |
| info | No S3 buckets found matching ⟨count⟩ naming patterns for ⟨host⟩ | No action. |
| info | S3 bucket discovery skipped — no host | No action. |
| info | S3 bucket exists (in a different region): ⟨name⟩ | No action — bucket presence noted for context. |

## Evidence the check records

- S3 bucket discovery skipped — no host: target: ⟨value⟩
- No S3 buckets found matching ⟨count⟩ naming patterns for ⟨host⟩: Tried: ⟨value⟩...
- S3 bucket publicly LISTABLE: ⟨name⟩: GET ⟨url⟩?list-type=2 -&gt; HTTP 200 (⟨value⟩ bytes of XML). Anyone can enumerate all object keys in the bucket. Even if objects are private, leaking the key names alone often reveals customer IDs / filenames / db dumps.
- S3 bucket exists (private list-ACL): ⟨name⟩: GET ⟨url⟩ -&gt; 403 (bucket exists, but list-ACL is private — good). Audit object-level ACLs separately: a bucket can be list-private but have public objects.
- S3 bucket exists (in a different region): ⟨name⟩: Redirect to: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## References

- primary: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/aws-amplify

## Run only this check

```
wpsecscan only s3_bucket_discovery https://example.com
```

`only` runs this check alone and prints its findings.
