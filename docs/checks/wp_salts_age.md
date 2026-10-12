---
id: wp_salts_age
title: "WP salts age check (#5+#6)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 154
---

# WP salts age check (#5+#6)

**check_id**: `wp_salts_age`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552 — Unsecured Credentials
**CWE**: CWE-261
**D3FEND**: D3-CR

## What it does

#5 + #6 — WordPress salts age check + nonce-randomness sampling.

Salts (`AUTH_KEY`, `SECURE_AUTH_KEY`, etc.) live in wp-config.php and should
be rotated periodically. We can't read wp-config remotely, but we CAN infer
rotation from nonce values — same salts → same nonces for the same action.

We sample wp-login nonces twice with a small delay, compare them, and flag
when they're identical (suggesting heavy cache OR static salts).

#6 = sample 50 nonces, compute collisions.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WordPress nonces identical across samples | Verify salts rotate. Regenerate with `wp salts create` (wp-cli) or the official generator at https://api.wordpress.org/secret-key/1.1/salt/ — drop the output into wp-config.php replacing the existing block. Old sessions invalidate (everyone has to re-log-in). |
| info | Salt-age probe — no nonces visible on /wp-login.php | No action. |
| info | Salt-age probe: ⟨count⟩ unique nonce(s) across ⟨count⟩ sample(s) | No action. |

## Evidence the check records

- Salt-age probe — no nonces visible on /wp-login.php: No `_wpnonce` field in the login form HTML.
- WordPress nonces identical across samples: Took ⟨count⟩ samples from /wp-login.php; all returned the same nonce ⟨value⟩... WP nonces incorporate a 12-24h tick — same value across multiple seconds is normal. But if it's still the same in 24h, suspect static salts (= forever-valid CSRF tokens).
- Salt-age probe: ⟨count⟩ unique nonce(s) across ⟨count⟩ sample(s): Nonces are rotating — salts appear active.

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## References

- https://api.wordpress.org/secret-key/1.1/salt/

## Run only this check

```
wpsecscan only wp_salts_age https://example.com
```

`only` runs this check alone and prints its findings.
