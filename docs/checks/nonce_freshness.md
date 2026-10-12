---
id: nonce_freshness
title: "WP nonce freshness audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 178
---

# WP nonce freshness audit

**check_id**: `nonce_freshness`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WP nonce freshness / rotation check.

WordPress nonces are tied to a (user, action, tick) tuple where tick is the
current 12-hour window. A fresh nonce should change every ~12 hours; a static
nonce (or one tied to nothing) is broken.

We fetch /wp-login.php twice and extract `_wpnonce` values, then a third time
after 1 second. If all three are identical, the nonce isn't tied to time and
likely isn't tied to user either — it's effectively static.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Same nonce value reused across different actions/paths | Make sure each form uses wp_nonce_field(&lt;action-name&gt;) with a UNIQUE action name. Avoid plugins that strip nonces or use static tokens. |
| info | No WP nonces visible to anonymous clients | No action needed. |
| info | Nonce on ⟨path⟩ is constant across 3 samples (expected within a 12-hour tick) | No action by itself — WP nonces are deliberately constant within a 12-hour window. Re-run this scan tomorrow to verify the nonce actually rotates. |
| info | Nonce on ⟨path⟩ rotates per-request | No action needed. |

## Evidence the check records

- No WP nonces visible to anonymous clients: Probed ⟨count⟩ pages; no `_wpnonce` field found.
- Same nonce value reused across different actions/paths: Multiple endpoints returned the same `_wpnonce`: ⟨value⟩ WP nonces should bind to a specific (user, action) tuple. Same value across actions means an attacker who acquires the nonce for one form can submit any form.
- Nonce on ⟨path⟩ is constant across 3 samples (expected within a 12-hour tick): Sampled ⟨count⟩ times within 1 sec; all returned: ⟨value⟩...
- Nonce on ⟨path⟩ rotates per-request: Three samples produced different values — the nonce includes a per-request element (good).

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.7
- **compliance_map / nist_800_53**: AC-12
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only nonce_freshness https://example.com
```

`only` runs this check alone and prints its findings.
