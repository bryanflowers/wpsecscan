---
id: csp_report_endpoint
title: "CSP report-uri/report-to endpoint health"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 101
---

# CSP report-uri/report-to endpoint health

**check_id**: `csp_report_endpoint`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1562 — Impair Defenses

## What it does

CSP `report-uri` / `report-to` endpoint health check.

A site with a Content-Security-Policy that points its violation reports
at a broken endpoint (404/5xx) gets zero visibility into CSP violations,
defeating the monitoring value of having a policy at all. This check
extracts the endpoint URL(s) from the CSP header and does a single HEAD
request to each to verify the reporting destination is reachable.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | CSP ⟨kind⟩ endpoint is unreachable | Either remove the broken reporting directive from your CSP, or fix the endpoint. A CSP whose violation reports go nowhere is a CSP whose monitoring value is zero — you have no visibility into real-world policy hits. |
| medium | CSP ⟨kind⟩ endpoint returns HTTP ⟨status⟩ | The endpoint declared by your CSP `⟨kind⟩` directive returns HTTP ⟨status⟩ — violation reports will be dropped. Verify the endpoint accepts POST requests (`report-uri`) or the Reporting API endpoint group is registered correctly. |
| info | CSP ⟨kind⟩ endpoint reachable (⟨status⟩) | No action. |

## Evidence the check records

- CSP ⟨kind⟩ endpoint is unreachable: HEAD ⟨target_url⟩ → connection error. CSP value: ⟨value⟩
- CSP ⟨kind⟩ endpoint returns HTTP ⟨status⟩: HEAD ⟨target_url⟩ → ⟨status⟩ CSP value: ⟨value⟩
- CSP ⟨kind⟩ endpoint reachable (⟨status⟩): HEAD ⟨target_url⟩ → ⟨status⟩

## Compliance mapping

- **compliance_map / pci_dss**: 10.2.1
- **compliance_map / nist_800_53**: AU-12
- **compliance_map / iso_27001**: A.8.15
- **compliance_v2 / hitrust**: 09.aa
- **compliance_v2 / cmmc**: AU.L2-3.3.1
- **compliance_v2 / nist_csf**: DE.AE-03
- **compliance_v2 / cis_v8**: 8.1
- **compliance_v2 / iso_27001_2022**: A.8.15

## Run only this check

```
wpsecscan only csp_report_endpoint https://example.com
```

`only` runs this check alone and prints its findings.
