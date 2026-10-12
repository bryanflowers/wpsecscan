---
id: hpp
title: "HTTP Parameter Pollution probe"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "Transport & headers"
words: 166
---

# HTTP Parameter Pollution probe

**check_id**: `hpp`
**aggressive**: yes
**category**: Transport & headers
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-235
**D3FEND**: D3-IVA

## What it does

H6 HTTP Parameter Pollution (HPP).

Sending duplicate query parameters can confuse servers that don't normalise:
  ?id=1&id=2  → backend reads `id=1`, WAF reads `id=2`, etc.
This is the classic technique for evading allow-list-based WAFs and for
triggering uncommon code paths in plugins that handle their own parameter
parsing.

We probe a few common endpoints with both `?id=normal` and `?id=normal&id=evil`
and look for behaviour differences (status code, body length, or `WAF blocked`
markers appearing in only one variant).

Aggressive only — the duplicate-param payloads include reserved values
(`<script>`, etc.) that some WAFs interpret as attacks.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | HTTP Parameter Pollution — ⟨count⟩ endpoint(s) treat duplicates differently | Normalize query parameters at the edge — pick the first or last occurrence and discard the rest, matching whatever the backend does. ModSecurity has `ARGS:id` matching; ensure CRS rules use `ARGS_NAMES` to catch all variants. |
| info | HTTP Parameter Pollution check skipped (passive mode) | No action. |
| info | HTTP Parameter Pollution — no differential observed | No action. |

## Evidence the check records

- HTTP Parameter Pollution check skipped (passive mode): Pass --aggressive to enable.
- HTTP Parameter Pollution — ⟨count⟩ endpoint(s) treat duplicates differently: ⟨value⟩ When status or body length changes between single- and duplicate-parameter requests, a WAF or middleware is reading a different value than the backend. Attackers use this to smuggle payloads past the WAF.
- HTTP Parameter Pollution — no differential observed: Probed ⟨count⟩ endpoints with duplicate parameters; no significant status/length delta.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## References

- primary: https://owasp.org/www-community/HTTP_Parameter_Pollution
- deep dive: https://book.hacktricks.xyz/pentesting-web/parameter-pollution

## Run only this check

```
wpsecscan only hpp https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
