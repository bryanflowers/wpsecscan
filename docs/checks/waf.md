---
id: waf
title: "WAF / CDN detection"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 75
---

# WAF / CDN detection

**check_id**: `waf`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Gather Victim Host Information: Client Configurations

## What it does

WAF / CDN detection.

Runs early. Stashes the detected WAF (if any) in ctx['shared']['waf'] so
aggressive checks downstream can interpret their results correctly.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | No WAF / CDN fingerprints detected | If you expect a WAF in front of this site, verify it's actually serving traffic for this hostname. |
| info | WAF / CDN detected: ⟨value⟩ | No action needed unless this is a misconfiguration. If you want a true picture of underlying app security, scan the origin directly (e.g. via /etc/hosts override to the origin IP) or whitelist your scanner IP in the WAF. |

## Evidence the check records

- WAF / CDN detected: ⟨value⟩: Detected via header/cookie fingerprints: ⟨lines⟩ Aggressive checks downstream may be intercepted by this layer — false-negatives are possible (the WAF blocks our probes before they reach WordPress).
- No WAF / CDN fingerprints detected: Headers, cookies, and a tripwire request did not match known WAF signatures.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/?q='<script>alert(1)</script>'
# wafw00f gives a more detailed fingerprint:
wafw00f https://example.com
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.16
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## References

- primary: https://portswigger.net/web-security/ssrf/bypassing-ssrf-filters

## Run only this check

```
wpsecscan only waf https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
