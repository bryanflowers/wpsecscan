---
id: referenced_buckets
title: "Referenced-bucket open-listing probe (S3/GCS/R2/Spaces)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 143
---

# Referenced-bucket open-listing probe (S3/GCS/R2/Spaces)

**check_id**: `referenced_buckets`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1530 — Data from Cloud Storage
**CWE**: CWE-732
**D3FEND**: D3-RAC

## What it does

Item #6 — extract cloud-bucket URLs referenced in the page HTML/JS and
probe each one for an open listing.

Complements `s3_bucket_discovery` which guesses bucket names from the
host. This check inspects what the site actually links to and asks the
question "does this referenced bucket leak its contents?" — covering
S3, Google Cloud Storage, Cloudflare R2, and DigitalOcean Spaces.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨value⟩ bucket publicly listable: ⟨value⟩ | — |
| info | No cloud-bucket URLs referenced in page source | No action needed. |
| info | ⟨count⟩ referenced bucket(s) — none publicly listable | No action needed. |

## Evidence the check records

- No cloud-bucket URLs referenced in page source: Scanned ⟨count⟩ pages for S3 / GCS / R2 / Spaces references.
- ⟨count⟩ referenced bucket(s) — none publicly listable: Probed each referenced bucket; none returned an enumerable listing. Buckets seen: ⟨value⟩
- ⟨value⟩ bucket publicly listable: ⟨value⟩: GET ⟨value⟩ -&gt; HTTP ⟨value⟩ (⟨value⟩ bytes). The bucket is referenced from this site and its contents can be enumerated by any anonymous visitor. Leaked object keys often expose customer IDs, internal filenames, database dumps, or staged backups.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## References

- https://storage.googleapis.com/

## Run only this check

```
wpsecscan only referenced_buckets https://example.com
```

`only` runs this check alone and prints its findings.
