---
id: bucket_shadow_takeover
title: "S3 / R2 / GCS shadow-bucket takeover (A15)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 166
---

# S3 / R2 / GCS shadow-bucket takeover (A15)

**check_id**: `bucket_shadow_takeover`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1583.006 — Web Services
**CWE**: CWE-1188
**D3FEND**: D3-DNS

## What it does

A15 (v2.6.0) — S3 / R2 / GCS shadow-bucket takeover.

The existing `referenced_buckets` check probes the buckets actually
referenced from HTML. This sibling check is offensive in the opposite
direction: it predicts likely bucket names from the site's slug and
probes whether they exist + are takeable (404 on the AWS/GCS endpoint
means the operator could have used the name but didn't — attacker can
register it and serve content from that name as if from the operator).

Probe set (per bucket host):
  - {slug}-uploads, {slug}-media, {slug}-backups, {slug}-staging,
    {slug}-dev, {slug}-cdn, {slug}.uploads, uploads-{slug}

Probe response semantics differ by provider:
  - S3:  404 + "NoSuchBucket" → registerable (CRITICAL)
  - GCS: 404 + "The specified bucket does not exist" → registerable
  - R2:  generic 404 (Cloudflare); no signal — skip

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨provider⟩ bucket name takeable: ⟨bucket_name⟩ | 1. Register the bucket yourself at ⟨provider⟩ (cost: ~$0/month for empty bucket). 2. Or, monitor for the name's registration via the CT-log shadow-cert check (A31) + DNS-monitoring. |

## Evidence the check records

- ⟨provider⟩ bucket name takeable: ⟨bucket_name⟩: ⟨provider⟩ responded 404 with '⟨marker⟩' for ⟨url⟩ This name resembles your site (⟨host⟩) and is unregistered. An attacker can register it and serve content from a name your customers may trust as 'official'.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: SC-20
- **compliance_map / iso_27001**: A.5.31

## Run only this check

```
wpsecscan only bucket_shadow_takeover https://example.com
```

`only` runs this check alone and prints its findings.
