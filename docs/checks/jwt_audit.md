---
id: jwt_audit
title: "JWT audit (alg=none + weak HS256)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 272
---

# JWT audit (alg=none + weak HS256)

**check_id**: `jwt_audit`
**aggressive**: no
**category**: Authentication & session
**max severity**: critical
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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | JWT issued with `alg=none` — unsigned token in use | Configure the JWT library to require RS256 or ES256. Reject `alg=none` at validation. WP JWT Auth plugins should NEVER allow this; if yours does, switch plugins. |
| critical | JWT signed with weak HS256 secret: ⟨cracked⟩ | Rotate the JWT signing secret immediately. Use a 256-bit random key (`openssl rand -hex 32`). Better: switch to RS256/ES256 with an asymmetric key. |
| critical | Server accepts `alg=none` JWT — full auth bypass | Disable `alg=none` acceptance. The JWT library is probably `firebase/php-jwt` or `lcobucci/jwt`; both have a `setAllowedAlgs()` method — set it to ['HS256','RS256','ES256'] EXPLICITLY. |
| medium | Endpoint responded 200 to an unsigned `alg=none` token — manual confirmation required | Request /wp-json/wp/v2/users/me with the tampered token and without any token and compare the bodies. If they differ and the first is a user object, disable `alg=none` acceptance (set allowed algorithms explicitly in the JWT library). |
| info | Found ⟨count⟩ JWT(s); all use signed algorithms with non-trivial secrets | No action. |
| info | No JWTs detected on probed pages | No action. |

## Evidence the check records

- No JWTs detected on probed pages: Scanned / wp-login.php /wp-json/ /wp-admin/admin-ajax.php for JWT-shaped tokens.
- Found ⟨count⟩ JWT(s); all use signed algorithms with non-trivial secrets: Tokens: ⟨count⟩; weak-secret + alg=none checks all clean.
- JWT issued with `alg=none` — unsigned token in use: Header: ⟨header⟩ Claims: ⟨claims⟩ An unsigned JWT means the server accepts ANY claims at face value. Anyone can mint a token with `sub: admin` and gain access.
- JWT signed with weak HS256 secret: ⟨cracked⟩: Token header: ⟨header⟩ Claims: ⟨claims⟩ HMAC-SHA256 secret was guessed from the top-50 list. An attacker can forge JWTs for any user.
- Server accepts `alg=none` JWT — full auth bypass: Sent a tampered token with `alg=none` to /wp-json/wp/v2/users/me; got HTTP 200 with a JSON user object. Original claims (re-used in the tampered token): ⟨claims⟩
- Endpoint responded 200 to an unsigned `alg=none` token — manual confirmation required: Sent a tampered token with `alg=none` to /wp-json/wp/v2/users/me; got HTTP 200, but the body is not a JSON user object, so an auth bypass is NOT confirmed. Original claims (re-used in the tampered token): ⟨claims⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-5(7)
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## References

- primary: https://jwt.io/
- deep dive: https://portswigger.net/web-security/jwt
- video: https://www.youtube.com/watch?v=3OpQi65s_ME

## Run only this check

```
wpsecscan only jwt_audit https://example.com
```

`only` runs this check alone and prints its findings.
