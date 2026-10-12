---
id: hibp
title: "HaveIBeenPwned lookup"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 161
---

# HaveIBeenPwned lookup

**check_id**: `hibp`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.001 — Gather Victim Identity: Credentials

## What it does

HaveIBeenPwned username breach lookup.

Consumes ctx['shared']['users'] (populated by checks/users.py).
Without --hibp-token: emits info findings with HIBP URLs the user can check manually.
With --hibp-token: queries the breachedaccount API and reports breaches found.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | User '⟨u⟩' appears in ⟨count⟩ known breach(es) | Force '⟨u⟩' to reset their password. Encourage password manager + 2FA. Consider mandatory rotation for any admin in this list. |
| info | HIBP lookup network error for '⟨u⟩' | Re-run later or check token quota. |
| info | HIBP lookup skipped — no usernames discovered | No action needed. |
| info | HIBP rate-limited — aborting remaining lookups | Wait a minute and re-run. |
| info | HIBP token is invalid or has no quota | Provide a valid --hibp-token. |
| info | No HIBP breaches found for ⟨queried⟩ discovered username(s) | No action needed. |
| info | ⟨count⟩ username(s) discoverable — check HIBP manually | Force a password rotation for any user whose account email appears in known breaches. Buy a HIBP key at haveibeenpwned.com/API/Key (~$3.95/mo) to automate this. |

## Evidence the check records

- HIBP lookup skipped — no usernames discovered: The user-enumeration check did not find any usernames to look up.
- ⟨count⟩ username(s) discoverable — check HIBP manually: Discovered usernames: ⟨lines⟩ Without a HIBP API token we can't query breaches automatically. Visit the links above (or pass --hibp-token &lt;key&gt;) to check each account.
- User '⟨u⟩' appears in ⟨count⟩ known breach(es): HIBP breaches: ⟨names⟩⟨value⟩ If this user reuses the breached password anywhere, the WP account is at risk.
- No HIBP breaches found for ⟨queried⟩ discovered username(s): Queried HIBP for: ⟨value⟩
- HIBP lookup network error for '⟨u⟩': ⟨value⟩: ⟨e⟩
- HIBP token is invalid or has no quota: API returned 401 — verify token at haveibeenpwned.com/API/Key.
- HIBP rate-limited — aborting remaining lookups: Got HTTP 429 after ⟨queried⟩ lookup(s).

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.5
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## References

- https://haveibeenpwned.com/api/v3/breachedaccount/
- https://haveibeenpwned.com/account/

## Run only this check

```
wpsecscan only hibp https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
