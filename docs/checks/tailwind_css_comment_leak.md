---
id: tailwind_css_comment_leak
title: "Tailwind/CSS filesystem-path leak (#69)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 54
---

# Tailwind/CSS filesystem-path leak (#69)

**check_id**: `tailwind_css_comment_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Tailwind/built-CSS comment leak audit.

Round-64 #69 — built CSS files (Tailwind, Sass output, esbuild bundles)
often leak filesystem paths from sourcemap comments or PostCSS plugins.
A typical signal is `/* C:\Users\... */` or `/home/<dev>/...` baked
into production CSS. Useful for an attacker doing username enumeration
or finding where to look for misconfigured staging hosts.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Filesystem-path leak in CSS comments: ⟨path⟩ | Strip comments + sourcemaps from production CSS. Tailwind: `npx tailwindcss --minify` PostCSS: enable `cssnano` with `discardComments: { removeAll: true }` esbuild: `--legal-comments=none` Reveals dev usernames + local dev-server ports. |

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only tailwind_css_comment_leak https://example.com
```

`only` runs this check alone and prints its findings.
