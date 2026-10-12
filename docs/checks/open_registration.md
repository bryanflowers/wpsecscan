---
id: open_registration
title: "Open registration without membership plugin"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 156
---

# Open registration without membership plugin

**check_id**: `open_registration`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authentication Failures
**MITRE ATT&CK**: T1136 — Create Account

## What it does

Detect publicly-open `?action=register` form, with FP filter for
intentional membership-plugin sites.

WordPress's "Anyone can register" setting flips this on. On a regular
blog/business site it's an attack vector — anonymous subscriber accounts
can probe authenticated endpoints, fill the database, exhaust mail
quotas, and provide a foothold for privilege escalation. On a
membership site (WooCommerce subscriptions, MemberPress, LearnDash) it's
intentional — we soften severity in that case.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Public WordPress registration is open (no membership plugin detected) | Disable open registration: Settings → General → uncheck 'Anyone can register'. Or via the CLI: wp option update users_can_register 0 Audit existing subscriber accounts for accounts you didn't create: wp user list --role=subscriber |
| info | Public registration enabled — membership plugin detected (likely intentional) | Verify Settings → General → 'New User Default Role' is set to `Subscriber`. Avoid the temptation to default to `Editor` or `Author` for friction-free onboarding — privilege escalation from those roles is far easier than from Subscriber. |

## Evidence the check records

- Public WordPress registration is open (no membership plugin detected): GET /wp-login.php?action=register → HTTP 200 with the standard registration form. 'Anyone can register' is enabled in Settings → General. No membership/LMS plugin was detected to justify the open registration, so this is most likely a leftover from initial setup.
- Public registration enabled — membership plugin detected (likely intentional): GET /wp-login.php?action=register returns the registration form (200), and an upstream check detected a membership/LMS plugin. This is the expected configuration; verify the role assigned to new registrations is `subscriber` not `editor`.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: AC-2
- **compliance_map / iso_27001**: A.5.16
- **compliance_v2 / hitrust**: 01.k
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.2
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan only open_registration https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
