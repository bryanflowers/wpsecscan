# WP salts age check (#5+#6)

**check_id**: `wp_salts_age`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only wp_salts_age
```
