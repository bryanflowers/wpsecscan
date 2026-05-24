# Service-port exposure: Redis/Memcache/DB (#B35-B37)

**check_id**: `service_exposure`
**aggressive**: no
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
wpsecscan --target https://example.com --only service_exposure
```
