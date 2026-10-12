---
id: ct_log_recent_certs
title: "CT-log recent unexpected cert issuances"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 151
---

# CT-log recent unexpected cert issuances

**check_id**: `ct_log_recent_certs`
**aggressive**: no
**category**: Transport & headers
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1583.003 — Acquire Infrastructure: Virtual Private Server

## What it does

Query Certificate-Transparency logs for unexpected recent cert issuances.

Every public certificate must be logged to a Certificate Transparency
(CT) log within hours of issuance. crt.sh aggregates these logs and
exposes a search API. Looking for `*.target.com` issuances in the last
30 days catches:
  - shadow-IT subdomains the site owner didn't create
  - subdomain takeovers that have already been TLS-provisioned
  - phishing-prep domains (typosquats issued under your name)

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low/info | CT logs show ⟨count⟩ cert(s) for *.⟨apex⟩ issued in last 30 days | Audit each entry against your records of intentional subdomain creation. Any unrecognised name should be investigated immediately. Set up an automated CT-monitor (Cert Spotter, Facebook CT API, or self-hosted crt.sh polling) to alert on new entries in near-real-time. |

## Evidence the check records

- CT logs show ⟨count⟩ cert(s) for *.⟨apex⟩ issued in last 30 days: crt.sh returned ⟨count⟩ distinct certificate names issued in the last 30 days for `*.⟨apex⟩`: ⟨lines⟩ ... and ⟨value⟩ more Verify each name is a subdomain you intentionally provisioned. Unexpected entries can indicate: - shadow-IT or rogue-employee deployments - a subdomain takeover where the attacker has provisioned a Let's Encrypt cert on a dangling-CNAME target - phishing-prep typosquats from a free issuer (rare; CAs validate apex ownership, but worth a sanity check).

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-17
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 09.s
- **compliance_v2 / cmmc**: SC.L2-3.13.10
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- https://crt.sh/?q=%25

## Run only this check

```
wpsecscan only ct_log_recent_certs https://example.com
```

`only` runs this check alone and prints its findings.
