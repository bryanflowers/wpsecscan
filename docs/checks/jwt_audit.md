# JWT audit (alg=none + weak HS256)

**check_id**: `jwt_audit`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials in Files
**CWE**: CWE-347
**D3FEND**: D3-CH

## What it does

JWT audit — decode + test weak HS256 secret + `alg=none` acceptance.

Walks the response Set-Cookie + body for JWT-shaped tokens (three dot-separated
base64url segments). For each token:
  1. Decode header + claims (no signature verification).
  2. Flag `alg=none` tokens (server allows unsigned tokens = full impersonation).
  3. Brute-force a TINY top-50 list of common HS256 secrets — if any matches,
     the server signed with a known-weak secret (`secret`, `password`, etc).
  4. Build a tampered `alg=none` token and POST it back to detect server-side
     `alg=none` acceptance.

Aggressive-only (sends a tampered token).

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-5(7)
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only jwt_audit
```
