---
id: permissions_policy
title: "Permissions-Policy header audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 121
---

# Permissions-Policy header audit

**check_id**: `permissions_policy`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1189 — Drive-by Compromise

## What it does

Permissions-Policy header audit.

`Permissions-Policy` (formerly Feature-Policy) declares which powerful
browser APIs (camera, microphone, geolocation, payment, USB, etc.) are
allowed on the site. Most WordPress sites don't need any of them on by
default. Missing or over-permissive grants are an attack-surface item for
malicious advertising / supply-chain JS.

We also flag the absence of `interest-cohort=()` which is the documented
opt-out for Google's FLoC tracking (GDPR / ePrivacy signal).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Permissions-Policy grants `*` to ⟨count⟩ sensitive directive(s) | Replace `*` with `()` (deny) or `(self)` (same-origin only) for directives the site doesn't use. Even if you embed a third party that needs camera/microphone, name them explicitly via `camera=(self "https://meet.example.com")` rather than `*`. |
| low | Permissions-Policy header missing | Add a deny-by-default header to disable powerful APIs you don't need. Example: `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()` — the `interest-cohort=()` clause also opts the site out of Google FLoC. |
| low | Permissions-Policy is set but does not opt out of FLoC (`interest-cohort=()`) | Append `, interest-cohort=()` to opt this site out of Google FLoC/Topics behaviour-tracking. Has near-zero impact and is a GDPR/ePrivacy good-practice signal. |
| info | Permissions-Policy header looks reasonable | No action. |

## Evidence the check records

- Permissions-Policy header missing: No Permissions-Policy header on /. Browsers will use defaults.
- Permissions-Policy grants `*` to ⟨count⟩ sensitive directive(s): Over-permissive directives: ⟨value⟩ Full header: ⟨value⟩
- Permissions-Policy is set but does not opt out of FLoC (`interest-cohort=()`): Header present but missing the `interest-cohort` directive: ⟨value⟩
- Permissions-Policy header looks reasonable: Header: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-18
- **compliance_map / iso_27001**: A.8.23
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.7
- **compliance_v2 / iso_27001_2022**: A.8.23

## Run only this check

```
wpsecscan only permissions_policy https://example.com
```

`only` runs this check alone and prints its findings.
