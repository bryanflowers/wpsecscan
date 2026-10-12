---
id: ssrf
title: "SSRF probes"
severity_max: high
severity_dynamic: true
aggressive: true
category: "SSRF / RCE / open access"
words: 59
---

# SSRF probes

**check_id**: `ssrf`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: high (some findings take their severity at run time)
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1090 — Proxy

## What it does

SSRF probes via WP/plugin endpoints that fetch URLs.

Common SSRF vectors:
  - oEmbed proxy `/wp-json/oembed/1.0/proxy?url=...`
  - WP image proxy or plugin endpoints (`/wp-json/<plugin>/v1/fetch?url=...`)
  - REST API edge cases

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (high, medium) | SSRF indicator at ⟨desc⟩ | Plugins that fetch URLs must validate them against an allow-list and reject RFC1918/loopback/link-local addresses. For oEmbed specifically, recent WP versions have hardened the proxy — make sure core and any oEmbed-handling plugin are current. |
| info | No SSRF indicators on tested endpoints | No action needed. |

## Evidence the check records

- No SSRF indicators on tested endpoints: Probed ⟨count⟩ known URL-fetching endpoints with an unresolvable canary host.
- SSRF indicator at ⟨desc⟩: GET ⟨path⟩ with ⟨param⟩=⟨SSRF_TARGET⟩ -&gt; HTTP ⟨value⟩ -&gt; ⟨why⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.21
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## References

- primary: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- deep dive: https://portswigger.net/web-security/ssrf
- https://wpsecscan-ssrf-canary.invalid/probe

## Run only this check

```
wpsecscan only ssrf https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
