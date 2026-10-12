---
id: prototype_pollution
title: "Prototype-pollution reflection probe"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 113
---

# Prototype-pollution reflection probe

**check_id**: `prototype_pollution`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

Prototype-pollution probe (client + server-side via JSON middleware).

Sends `?__proto__[polluted]=wpsec` and `?constructor[prototype][polluted]=wpsec`
style payloads. If the value is reflected in a response or appears in a
Set-Cookie / response header / inline JSON config, the server's JSON parsing
or merge utility is vulnerable.

Aggressive-only (sends crafted URL parameters).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Prototype-pollution candidate at ⟨path⟩ via `⟨key⟩` | Reject parameter names containing `__proto__`, `prototype`, or `constructor` at the entry point (e.g. plugin REST controller). For client-side: update jQuery to &gt;=3.4.0 and lodash to &gt;=4.17.12 (both have prototype-pollution fixes). |
| info | No prototype-pollution reflections detected | No action. |
| info | Prototype-pollution probe skipped (requires --aggressive) | No action. |

## Evidence the check records

- Prototype-pollution probe skipped (requires --aggressive): This check sends crafted query parameters; opt in via --aggressive.
- No prototype-pollution reflections detected: Probed ⟨count⟩ paths with ⟨count⟩ payload shape(s); none reflected the canary `⟨canary⟩`.
- Prototype-pollution candidate at ⟨path⟩ via `⟨key⟩`: Sent `?⟨key⟩=⟨canary⟩` to ⟨path⟩; canary ⟨ev⟩. If this value reaches a JavaScript merge utility (jQuery.extend, lodash.merge, Object.assign with untrusted input) it can corrupt Object.prototype globally.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://learn.snyk.io/lesson/prototype-pollution/

## Run only this check

```
wpsecscan only prototype_pollution https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
