---
id: debug_log_pii_sniff
title: "debug.log PII content sniff"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Other"
words: 119
---

# debug.log PII content sniff

**check_id**: `debug_log_pii_sniff`
**aggressive**: no
**category**: Other
**max severity**: critical
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1530 — Data from Cloud Storage Object

## What it does

When /wp-content/debug.log is exposed, look for PII in the first 4 KB.

The existing exposed_files check flags `wp-content/debug.log` on a 200
response. This check downloads the first 4 KB and scans for email
addresses, credit-card-shaped digits, and US/UK national-ID patterns.
A debug log containing real customer PII is a GDPR/PCI-DSS reportable
incident, not just an "info disclosure" finding.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high | /wp-content/debug.log contains personal data (⟨value⟩) | 1. IMMEDIATELY: block /wp-content/debug.log at the web server (nginx: `location = /wp-content/debug.log { deny all; }`). 2. Rotate the log somewhere outside the web root: in wp-config.php `define('WP_DEBUG_LOG', '/var/log/wp/debug.log');`. 3. Set `define('WP_DEBUG_DISPLAY', false);` so errors never reach page bodies. 4. Assess the leak scope: how many visitors could have downloaded the file in the exposure window. GDPR Article 34 notification may be required if individuals' rights are impacted. |

## Evidence the check records

- /wp-content/debug.log contains personal data (⟨value⟩): Public-readable debug.log has identifiable content in the first 4 KB: - ⟨count⟩ email(s): ⟨value⟩*** + others - ⟨count⟩ 13-19 digit string(s): ⟨value⟩*** - ⟨count⟩ IP address(es) A debug log with customer PII (emails) is a GDPR processing record that needs to be either secured or deleted; with card-shaped digit strings it's a PCI-DSS reportable incident.

## Compliance mapping

- **compliance_map / pci_dss**: 10.5.1
- **compliance_map / nist_800_53**: AU-9
- **compliance_map / iso_27001**: A.8.15
- **compliance_v2 / hitrust**: 09.aa
- **compliance_v2 / cmmc**: AU.L2-3.3.1
- **compliance_v2 / nist_csf**: DE.AE-03
- **compliance_v2 / cis_v8**: 8.5
- **compliance_v2 / iso_27001_2022**: A.8.15

## Run only this check

```
wpsecscan only debug_log_pii_sniff https://example.com
```

`only` runs this check alone and prints its findings.
