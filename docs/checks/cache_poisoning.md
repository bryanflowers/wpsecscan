---
id: cache_poisoning
title: "Web-cache poisoning probe"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 68
---

# Web-cache poisoning probe

**check_id**: `cache_poisoning`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Web-cache poisoning probe.

Sends requests with attacker-controlled headers (X-Forwarded-Host,
X-Original-URL, X-Rewrite-URL) and looks for the value being reflected in
the response. If the response is cacheable (Cache-Control: public, Age
header growing), the attacker's value can be served to other visitors.

Defensive probe only — we never poison anything; we just confirm whether
the headers ARE reflected.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium | Cache-poisoning candidate: ⟨header⟩ reflected in response | At the CDN / reverse proxy, strip attacker-controllable Host-rewrite headers (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL) before they reach origin. On Cloudflare: Transform Rules → Remove header. If the headers must reach origin, they MUST be added to the cache key (Vary header). Reference: https://portswigger.net/web-security/web-cache-poisoning |
| info | No web-cache poisoning indicators detected | No action. |

## Evidence the check records

- No web-cache poisoning indicators detected: Probed ⟨count⟩ attacker-controlled headers; none reflected.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.16
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- primary: https://portswigger.net/web-security/web-cache-poisoning

## Run only this check

```
wpsecscan only cache_poisoning https://example.com
```

`only` runs this check alone and prints its findings.
