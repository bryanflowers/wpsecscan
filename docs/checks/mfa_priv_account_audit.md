---
id: mfa_priv_account_audit
title: "MFA on privileged accounts (companion) (#63)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 105
---

# MFA on privileged accounts (companion) (#63)

**check_id**: `mfa_priv_account_audit`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078.001 — Default Accounts
**CWE**: CWE-308
**D3FEND**: D3-MFA

## What it does

MFA audit on privileged accounts (companion-plugin assisted).

Round-64 #63 — every administrator + editor account should have MFA
(WebAuthn / TOTP / hardware key) enabled. There's no way to enumerate
this from the outside, so this check calls
/wp-json/wpsecscan-companion/v1/mfa-status which the companion plugin
exposes. The plugin returns: [{user_id, login, role, mfa_enabled,
mfa_method}]. We flag any administrator without MFA.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Privileged account without MFA: ⟨value⟩ (⟨value⟩) | Enable MFA on every administrator/editor account. Top WP MFA plugins: - WP 2FA (recommended; supports WebAuthn + TOTP + recovery codes) - Two Factor (core team plugin) - Wordfence Login Security Enforce MFA at the role level (admin can't login without it). |
| info | All ⟨count⟩ accounts in priv roles have MFA enabled (good) | Re-run after any new admin/editor account is added. |
| info | Companion plugin MFA-status endpoint requires auth | Configure the companion shared secret in wpsecscan sites config. |

## Evidence the check records

- Companion plugin MFA-status endpoint requires auth: GET /wp-json/wpsecscan-companion/v1/mfa-status -&gt; ⟨value⟩
- All ⟨count⟩ accounts in priv roles have MFA enabled (good): Checked ⟨count⟩ accounts; 0 priv accounts without MFA
- Privileged account without MFA: ⟨value⟩ (⟨value⟩): User ⟨value⟩ (id ⟨value⟩) — role ⟨value⟩ — MFA disabled

## Compliance mapping

- **compliance_map / pci_dss**: 8.4.2
- **compliance_map / nist_800_53**: IA-2(1)
- **compliance_map / iso_27001**: A.8.5

## Run only this check

```
wpsecscan only mfa_priv_account_audit https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
