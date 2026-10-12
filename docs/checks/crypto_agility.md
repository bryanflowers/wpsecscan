---
id: crypto_agility
title: "Crypto agility — PQ/TLS 1.3 hybrid/cert inventory (#47-51)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 171
---

# Crypto agility — PQ/TLS 1.3 hybrid/cert inventory (#47-51)

**check_id**: `crypto_agility`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-326
**D3FEND**: D3-CH

## What it does

Round-59 #47-51 — Crypto agility audit.

#47 Post-quantum cipher — does the server advertise any hybrid PQ
   key-exchange (X25519MLKEM768 / X25519Kyber768Draft00) in TLS?
#48 Hybrid TLS 1.3 — confirm TLS 1.3 with hybrid KEX
#49 Crypto inventory — list cert SAN, public-key algorithm + size, sig
   algorithm, OCSP-must-staple flag
#50 RSA key size — flag &lt;2048 bit RSA certs (still common on old hosts)
#51 Curve preference — server advertises which ECDH curves?

All best-effort via stdlib `ssl` + optional `cryptography` parse. We
avoid pulling in heavy deps.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | RSA cert key size only ⟨value⟩ bits | Reissue cert with RSA &gt;=2048 (ideally 3072) or ECDSA P-256/P-384. Sub-2048 RSA is below NIST baseline since 2013. |
| medium | TLS version is ⟨value⟩, not TLS 1.3 | Enable TLS 1.3. Required for post-quantum hybrid KEX. |
| low | Crypto-agility: TLS handshake failed | Investigate connectivity. |
| info | Crypto inventory | No action. |
| info | Crypto-agility skipped (no host) | No action. |
| info | Curve preference — best assessed via test endpoint | Prefer X25519 + P-256 + P-384. Disable P-192 (legacy). |
| info | Post-quantum KEX support — manual confirmation needed | Cloudflare / Google enable X25519MLKEM768 by default. If self-hosting nginx, upgrade to OpenSSL 3.5+ and add `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;`. |

## Evidence the check records

- Post-quantum KEX support — manual confirmation needed: Python stdlib ssl can't introspect the group. Test with: openssl s_client -tls1_3 -groups X25519MLKEM768 -connect ⟨host⟩:443
- Crypto inventory: subject=⟨value⟩ sans=⟨count⟩ (first 3: ⟨value⟩) key=⟨value⟩ ⟨value⟩ bits sig=⟨value⟩ must-staple=⟨value⟩
- Curve preference — best assessed via test endpoint: Use https://www.ssllabs.com/ssltest/analyze.html?d=⟨host⟩ to see the offered curves and the server's preference order.
- Crypto-agility: TLS handshake failed: host=⟨host⟩
- TLS version is ⟨value⟩, not TLS 1.3: Negotiated: ⟨value⟩
- RSA cert key size only ⟨value⟩ bits: key_bits=⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-13
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.312(e)(2)(ii)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-13
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- https://www.ssllabs.com/ssltest/analyze.html?d=

## Run only this check

```
wpsecscan only crypto_agility https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
