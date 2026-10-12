---
id: amp_transitional_redirect
title: "AMP plugin transitional-mode open-redirect (A19)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 100
---

# AMP plugin transitional-mode open-redirect (A19)

**check_id**: `amp_transitional_redirect`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1566.002 — Spearphishing Link
**CWE**: CWE-601
**D3FEND**: D3-NTA

## What it does

A19 (v2.6.0) — AMP plugin transitional-mode open-redirect probe.

The `amp` plugin (Google AMP for WP) in 'Transitional' mode serves an
AMP variant at `?amp=1` for any URL. Some theme/AMP-plugin combinations
mishandle the redirect when `?amp=1` is paired with an open URL
parameter — the user's intended URL leaks via `Location:` header.

Passive: probe `/?amp=1&redirect_to=https://evil.example/` and check
whether the response 30x to `evil.example`.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | AMP plugin honours external redirect parameter: ⟨path⟩ | Update the AMP plugin to the latest version. If your theme implements a custom AMP redirect, validate redirect targets against an allow-list of internal paths. |

## Evidence the check records

- AMP plugin honours external redirect parameter: ⟨path⟩: GET ⟨path⟩ → HTTP ⟨value⟩ Location: ⟨loc⟩ The AMP plugin or theme forwards the user to an arbitrary external URL specified in the query string. This is a phishing-toolkit primitive.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## References

- https://wpsecscan-probe.example/

## Run only this check

```
wpsecscan only amp_transitional_redirect https://example.com
```

`only` runs this check alone and prints its findings.
