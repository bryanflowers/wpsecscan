# Host port recon — Docker/Redis/k8s/etc. (#40)

**check_id**: `host_recon`
**aggressive**: no
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
wpsecscan --target https://example.com --only host_recon
```
