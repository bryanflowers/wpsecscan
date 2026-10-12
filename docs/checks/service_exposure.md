---
id: service_exposure
title: "Service-port exposure: Redis/Memcache/DB (#B35-B37)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 167
---

# Service-port exposure: Redis/Memcache/DB (#B35-B37)

**check_id**: `service_exposure`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1046 — Network Service Discovery
**CWE**: CWE-668
**D3FEND**: D3-NTA

## What it does

Round-62 #B35-B37 — service-port exposure (Redis / Memcache / Elasticsearch /
DB ports) on the WP-host's IP.

Defensive intent: many WP hosts run Redis / Memcache / Elasticsearch for
caching / search on the SAME server as Apache+PHP. If the bind address
is 0.0.0.0 (not 127.0.0.1), those ports are reachable from the public
internet — catastrophic.

We don't run a port scan from the scanner host (network-noisy, often
breaks the user's own egress rules). Instead we:
  - resolve the target hostname
  - try a single 1-second TCP connect to each suspect port
  - if it opens, that's evidence the port is publicly bound

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high | ⟨label⟩ reachable on ⟨host⟩:⟨port⟩ | — |
| info | Service-port exposure — no high-risk ports open | No action. |
| info | Service-port exposure — skipped for local target | No action. |
| info | Service-port exposure — skipped for private/RFC1918 target | No action. |

## Evidence the check records

- Service-port exposure — skipped for local target: host=⟨host⟩
- Service-port exposure — skipped for private/RFC1918 target: host=⟨host⟩ resolved to ⟨resolved_ip⟩ (private range). Set WPSECSCAN_SCAN_LAN=1 to override (will probe 14 well-known service ports).
- Service-port exposure — no high-risk ports open: Probed ⟨count⟩ suspect ports on ⟨host⟩.
- ⟨label⟩ reachable on ⟨host⟩:⟨port⟩: TCP connect to ⟨host⟩:⟨port⟩ succeeded within 1s — service is publicly bound.

## Compliance mapping

- **compliance_map / pci_dss**: 1.2.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.21
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.AC-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.21

## Run only this check

```
wpsecscan only service_exposure https://example.com
```

`only` runs this check alone and prints its findings.
