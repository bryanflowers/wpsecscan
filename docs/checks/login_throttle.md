---
id: login_throttle
title: "Login rate-limiting test"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 125
---

# Login rate-limiting test

**check_id**: `login_throttle`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.003 — Brute Force: Password Spraying

## What it does

Login-throttling defense test.

Sends 6 deliberately-wrong logins for a synthetic non-existent user.
If the site rate-limits / shows a captcha by attempt #6, throttling works.
If all 6 attempts return identical 'invalid credentials' pages, the site
isn't throttling.

This is NOT brute force: same wrong password each time, single fake user.
Never enumerates passwords.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | No login rate-limiting detected | Install a rate-limiting plugin (Wordfence, Limit Login Attempts Reloaded, iThemes Security). At the server level, fail2ban with a wp-login.php pattern is also effective. Enable 2FA on all administrator accounts for defense in depth. |
| info | Login throttling kicked in at attempt #⟨throttle_detected_at⟩ (defense works) | No action needed — throttling is the defense working as intended. |
| info | Login-throttle test skipped — ⟨value⟩ can ban scanner IP | Allowlist your scanner IP in the security plugin, then re-run with --ignore-lockout-risk. |
| info | Login-throttling test skipped: /wp-login.php not reachable | No action needed. |

## Evidence the check records

- Login-throttle test skipped — ⟨value⟩ can ban scanner IP: Detected: ⟨value⟩. Sending ⟨ATTEMPTS⟩ wrong logins would trigger their IP ban policy before the test could conclude.
- Login-throttling test skipped: /wp-login.php not reachable: GET /wp-login.php -&gt; ⟨value⟩
- Login throttling kicked in at attempt #⟨throttle_detected_at⟩ (defense works): Sent ⟨throttle_detected_at⟩ wrong-password attempts for synthetic user '⟨canary_user⟩'. Attempt #⟨throttle_detected_at⟩ returned a throttle response (HTTP ⟨value⟩). Brute-force is meaningfully harder against this site.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17
- **compliance_extra / hipaa**: 164.312(d)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.r
- **compliance_v2 / cmmc**: AC.L2-3.1.8
- **compliance_v2 / nist_csf**: PR.AA-03
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.8.5

## Run only this check

```
wpsecscan only login_throttle https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
