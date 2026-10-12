---
id: cloud_metadata_ssrf
title: "Cloud-metadata SSRF chain (needs SSRF candidate)"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "SSRF / RCE / open access"
words: 189
---

# Cloud-metadata SSRF chain (needs SSRF candidate)

**check_id**: `cloud_metadata_ssrf`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: critical
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**CWE**: CWE-918
**D3FEND**: D3-NTA

## What it does

H1 Cloud-metadata SSRF chain.

If a previous SSRF check confirmed the target fetches attacker-controlled URLs,
this check escalates by asking the server to fetch cloud-metadata endpoints for
AWS / GCP / Azure / DigitalOcean / Hetzner / Oracle / Alibaba. A reply that
mirrors the metadata format is proof the server can be used as a confused
deputy to exfiltrate IAM tokens.

Aggressive only — runs ONLY when the ssrf check has already flagged a confirmed
or suspected SSRF parameter (avoids blind probing of every URL parameter).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | CONFIRMED cloud-metadata SSRF — ⟨count⟩ provider(s) reachable | 1. Fix the underlying SSRF (allow-list outbound URLs to a fixed set of trusted domains). 2. Force IMDSv2 on AWS (`HttpTokens=required`) — IMDSv1 has no auth. 3. Block egress to 169.254.169.254 / 100.100.100.200 from the application's network namespace. 4. For Kubernetes/Docker: NetworkPolicy denying egress to the metadata + control-plane CIDRs. |
| info | Cloud-metadata SSRF chain skipped (no confirmed SSRF candidate) | No action. |
| info | Cloud-metadata SSRF chain skipped (passive mode) | No action. |
| info | Cloud-metadata SSRF chain — no providers reachable | Still fix the SSRF — it can target internal services beyond just metadata. |

## Evidence the check records

- Cloud-metadata SSRF chain skipped (passive mode): Pass --aggressive AND have a confirmed SSRF candidate.
- Cloud-metadata SSRF chain skipped (no confirmed SSRF candidate): The ssrf check must confirm a parameter that fetches attacker URLs before this chain runs.
- CONFIRMED cloud-metadata SSRF — ⟨count⟩ provider(s) reachable: Via the SSRF-vulnerable parameter, the server fetched and returned cloud-metadata: ⟨value⟩ An attacker can use this to steal IAM tokens, dump instance configuration, or — if Docker/Kubernetes is reachable — escape into the cluster.
- Cloud-metadata SSRF chain — no providers reachable: Tried ⟨count⟩ cloud-metadata endpoints via the confirmed SSRF parameter; none returned recognisable metadata.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.6
- **compliance_extra / fedramp**: SC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## References

- primary: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
- deep dive: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
- video: https://www.youtube.com/watch?v=jBgnTd0jD4M

## Run only this check

```
wpsecscan only cloud_metadata_ssrf https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
