---
id: rest_permission_audit
title: "REST permission_callback audit (#3)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 79
---

# REST permission_callback audit (#3)

**check_id**: `rest_permission_audit`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-RAC

## What it does

#3 WP REST `permission_callback` audit.

Fetches /wp-json/ + every namespace's route listing, then probes each
route with GET (no auth). Flags routes that respond 200 (open) when
their `methods` list includes POST/PUT/DELETE (privileged actions
usually need auth). Many plugins omit `permission_callback` or use
`return true` — those routes leak data + accept writes.

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | REST: ⟨count⟩ privileged route(s) accept unauth GET | For each route, add `'permission_callback' => function() { return current_user_can('edit_posts'); }` (or stricter capability) in the plugin's `register_rest_route` call. `__return_true` is never appropriate for write methods. |
| info | REST permission audit — /wp-json/ inaccessible | No action. |
| info | REST permission audit — ⟨count⟩ privileged route(s) clean | No action. |

## Evidence the check records

- REST permission audit — /wp-json/ inaccessible: No namespaces returned.
- REST permission audit — ⟨count⟩ privileged route(s) clean: All privileged routes correctly rejected unauth GET.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L2-3.1.5
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.5.15

## Run only this check

```
wpsecscan only rest_permission_audit https://example.com
```

`only` runs this check alone and prints its findings.
