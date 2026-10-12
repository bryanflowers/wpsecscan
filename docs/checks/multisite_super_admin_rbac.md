---
id: multisite_super_admin_rbac
title: "Multisite super-admin RBAC bypass probe (F13)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 66
---

# Multisite super-admin RBAC bypass probe (F13)

**check_id**: `multisite_super_admin_rbac`
**aggressive**: no
**category**: Authentication & session
**max severity**: low
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078.003 — Local Accounts
**CWE**: CWE-269
**D3FEND**: D3-IAA

## What it does

F13 (v2.8.1) — Multisite super-admin RBAC bypass probe.

Some multisite-aware plugins (notably User Role Editor pre-4.64,
Members pre-3.2.6) allowed regular admins to grant themselves
super-admin via a REST/AJAX endpoint that omitted the
`is_super_admin()` check. We probe for those endpoints and emit
a low-severity advisory if found (full exploitation requires
auth, which we don't have).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | F13: role-editor plugin endpoint exposed at ⟨p⟩ | Update User Role Editor &gt;= 4.64 and Members &gt;= 3.2.6. Audit any custom role-editor plugins for missing `is_super_admin()` guards on role-modification endpoints. |

## Evidence the check records

- F13: role-editor plugin endpoint exposed at ⟨p⟩: GET ⟨p⟩ → ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.2
- **compliance_map / nist_800_53**: AC-6
- **compliance_map / iso_27001**: A.8.2
- **compliance_v2 / hitrust**: 01.q
- **compliance_v2 / cmmc**: AC.L2-3.1.5
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 6.8
- **compliance_v2 / iso_27001_2022**: A.8.2

## Run only this check

```
wpsecscan only multisite_super_admin_rbac https://example.com
```

`only` runs this check alone and prints its findings.
