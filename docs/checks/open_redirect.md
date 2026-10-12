---
id: open_redirect
title: "Open-redirect probes"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "SSRF / RCE / open access"
words: 62
---

# Open-redirect probes

**check_id**: `open_redirect`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1204.001 — User Execution: Malicious Link

## What it does

Open-redirect probes on /wp-login.php?redirect_to= and common variants.

WP core's wp_safe_redirect() filters off-host destinations, but custom themes
and plugins sometimes ship their own redirect handlers that don't.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Open redirect via ⟨desc⟩ | Validate redirect targets against an allow-list, or use wp_safe_redirect() which strips off-host destinations. Open redirects are commonly chained into phishing campaigns and OAuth-token theft. |
| info | No open-redirect vectors found on common parameters | No action needed. |

## Evidence the check records

- No open-redirect vectors found on common parameters: Probed ⟨count⟩ common redirect parameter patterns.
- Open redirect via ⟨desc⟩: GET ⟨path⟩ with ⟨params⟩ -&gt; ⟨value⟩ Location: ⟨loc⟩ Target host '⟨target_host⟩' is not the scanned host '⟨scan_host⟩'.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://cwe.mitre.org/data/definitions/601.html
- deep dive: https://portswigger.net/kb/issues/00500100_open-redirection-reflected
- https://wpsecscan-redirect-test.invalid/landed

## Run only this check

```
wpsecscan only open_redirect https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
