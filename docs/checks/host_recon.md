---
id: host_recon
title: "Host port recon — Docker/Redis/k8s/etc. (#40)"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "Discovery & enumeration"
words: 196
---

# Host port recon — Docker/Redis/k8s/etc. (#40)

**check_id**: `host_recon`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1046 — Network Service Discovery
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#40 — container / cloud-native host recon.

When the WP site is hosted in a container or on a cloud VM, the underlying
host has its own attack surface (open Redis, exposed Docker socket, naked
Kubernetes API). This check probes a small set of cloud-host common ports
+ known-bad service-discovery endpoints AGAINST THE TARGET'S IP — not
side-channel scanning, just confirming what the WP-host port surface
looks like from the public internet.

Passive — TCP-only connect probes, no payload-sending. Aggressive mode
extends to send a couple of read-only fingerprint queries.

Out of scope: actual CVE matching against the discovered service banners
— that's a job for Trivy / nmap. We emit info-level findings telling the
user "consider running a host scanner against $IP".

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, info) | Host recon — ⟨count⟩ ⟨sev_level⟩-risk service(s) reachable on ⟨host⟩ | Restrict the listed ports to a private network / VPN. If they MUST be reachable, ensure authentication is enabled (Redis requirepass, MongoDB --auth, Docker TLS client certs, Kubernetes RBAC). Run a full Trivy / nmap scan to audit further. |
| info | Host recon skipped (no hostname) | No action. |
| info | Host recon — no non-HTTP ports open on ⟨host⟩ | — |

## Evidence the check records

- Host recon skipped (no hostname): Couldn't parse hostname from target.
- Host recon — no non-HTTP ports open on ⟨host⟩: Probed ⟨count⟩ common service ports; none accepted a TCP connection.
- Host recon — ⟨count⟩ ⟨sev_level⟩-risk service(s) reachable on ⟨host⟩: ⟨value⟩ These services live on the same IP as the WP site. Exposing them publicly is rarely intentional; in cloud setups they're meant to be locked behind a VPN or security group.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-04
- **compliance_v2 / cis_v8**: 1.1
- **compliance_v2 / iso_27001_2022**: A.5.9

## Run only this check

```
wpsecscan only host_recon https://example.com
```

`only` runs this check alone and prints its findings.
