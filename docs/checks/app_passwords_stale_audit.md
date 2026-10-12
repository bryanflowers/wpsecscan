---
id: app_passwords_stale_audit
title: "Application Passwords stale-token audit (A8, auth)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 139
---

# Application Passwords stale-token audit (A8, auth)

**check_id**: `app_passwords_stale_audit`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-1392
**D3FEND**: D3-CRO

## What it does

A8 (v2.6.0) — App Passwords stale-token audit.

The existing `app_passwords` check is passive (feature-on/off). This
sibling check runs ONLY when the scanner has authenticated session
data (cookies from authenticated.py OR a companion-plugin token), and
lists every user's stored Application Passwords with:

  • Age in days (&gt;180 = stale, recommended for rotation).
  • last_used date if WP recorded it (the field exists since WP 6.2).
  • Whether the AP was created from an unusual user-agent (mobile,
    automation-tool, etc.) per the `name` field operators tend to set.

The output is a list of {user, name, age_days, last_used_days_ago}
findings, scored medium per stale AP.

Defaults to no-op without auth, so it's safe to keep in ALL_CHECKS.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | Application Password stale: user '⟨name⟩' / token '⟨ap_name⟩' | 1. Confirm with the user that this AP is still needed. 2. If not, revoke at /wp-admin/profile.php → Application Passwords → Revoke. 3. If still needed, rotate the token (revoke + reissue) and update the integration that uses it. 4. Set an organisation policy: any AP unused for &gt;90d is auto-revoked via wp-cron. |

## Evidence the check records

- Application Password stale: user '⟨name⟩' / token '⟨ap_name⟩': User: ⟨name⟩ (id=⟨uid⟩) AP name: ⟨ap_name⟩ Created: ⟨value⟩ (⟨age⟩ days ago) Last used: ⟨value⟩ (⟨last⟩ days ago)

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.7
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.16

## Run only this check

```
wpsecscan only app_passwords_stale_audit https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
