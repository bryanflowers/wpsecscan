---
id: nextjs_env_var_exposure
title: "Next.js NEXT_PUBLIC_* secret-leak probe (F16)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 84
---

# Next.js NEXT_PUBLIC_* secret-leak probe (F16)

**check_id**: `nextjs_env_var_exposure`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-200
**D3FEND**: D3-CRO

## What it does

F16 (v2.8.1) — Next.js NEXT_PUBLIC_* env-var exposure probe.

Headless WP + Next.js sites bake `NEXT_PUBLIC_*` env vars into
the static chunks under `/_next/static/chunks/`. Developers often
accidentally label a private secret with the `NEXT_PUBLIC_` prefix,
which then ships to every client. We sniff a webpack chunk for
suspicious tokens.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | F16: Next.js chunk leaks secret (⟨label⟩) | Rename the env var to remove the `NEXT_PUBLIC_` prefix so Next.js stops embedding it in the client bundle. Rotate the leaked secret IMMEDIATELY. Re-build and re-deploy. |
| info | F16: Next.js _next/ assets not detected | No action needed. |
| info | F16: no obvious secret patterns in Next.js chunks | No action needed. |

## Evidence the check records

- F16: Next.js _next/ assets not detected: No /_next/static/buildManifest.js — not a Next.js site.
- F16: no obvious secret patterns in Next.js chunks: Inspected ⟨count⟩ chunk(s).
- F16: Next.js chunk leaks secret (⟨label⟩): /_next/⟨chunk⟩: matched ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.4
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: CM.L2-3.4.6
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only nextjs_env_var_exposure https://example.com
```

`only` runs this check alone and prints its findings.
