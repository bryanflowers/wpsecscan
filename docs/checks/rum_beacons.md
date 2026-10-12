---
id: rum_beacons
title: "RUM beacon library detection"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 102
---

# RUM beacon library detection

**check_id**: `rum_beacons`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: low
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1593 — Search Open Websites/Domains

## What it does

Detect Real-User-Monitoring (RUM) beacon libraries in page source.

RUM beacons send full URL paths (including query strings) plus timing
data to vendor cloud endpoints. The query strings may include
sensitive identifiers like ?email=, ?reset_key=, ?token= that the
site owner thought were transient. Privacy inventory item.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Real-User-Monitoring beacon(s) active: ⟨value⟩ | Privacy inventory item — verify each vendor is on your data-processor list (GDPR Article 28 / DPA). Audit whether sensitive query-string parameters (?email=, ?token=, ?reset_key=) flow through pages where the RUM library is active. Most RUM vendors support URL-redaction filters — configure them. |

## Evidence the check records

- Real-User-Monitoring beacon(s) active: ⟨value⟩: Detected RUM library/libraries in homepage source: ⟨value⟩ RUM beacons send the full visited URL (including query strings) plus timing data to the vendor's cloud endpoint. If your site uses URL parameters for password-reset keys, magic-login links, account-switch tokens, etc., those parameters end up in the RUM provider's log — outside your control.

## Compliance mapping

- **compliance_map / pci_dss**: 12.8.1
- **compliance_map / nist_800_53**: SA-12
- **compliance_map / iso_27001**: A.5.19
- **compliance_v2 / hitrust**: 05.h
- **compliance_v2 / cmmc**: RA.L2-3.11.1
- **compliance_v2 / nist_csf**: ID.SC-01
- **compliance_v2 / cis_v8**: 15.1
- **compliance_v2 / iso_27001_2022**: A.5.19

## Run only this check

```
wpsecscan only rum_beacons https://example.com
```

`only` runs this check alone and prints its findings.
