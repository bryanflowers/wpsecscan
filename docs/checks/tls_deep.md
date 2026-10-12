---
id: tls_deep
title: "Deep TLS audit"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 208
---

# Deep TLS audit

**check_id**: `tls_deep`
**aggressive**: no
**category**: Transport & headers
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Deep TLS audit — one handshake, all the checks.

Covers everything beyond the basic version-and-expiry that `tls_headers` does:
  - Weak protocol acceptance (TLSv1, TLSv1.1, SSLv3, SSLv2 → PCI-DSS bans)
  - Weak cipher tokens (RC4, 3DES, NULL, EXPORT, MD5, anon)
  - Negotiated cipher AEAD / forward-secrecy
  - Self-signed indicators (subject == issuer)
  - SubjectAltName list coverage
  - Certificate expiry tiering (expired → critical; &lt;14d → high; &lt;30d → medium)

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | TLS certificate EXPIRED ⟨value⟩ days ago | Renew immediately. If using Let's Encrypt, check certbot/renewal cron. |
| high | Self-signed certificate at ⟨host⟩ | Issue a real cert from Let's Encrypt (`certbot`) or your provider. Self-signed certs train users to dismiss browser warnings. |
| high | TLS certificate expires in ⟨days⟩ days | Renew NOW. Verify auto-renew is configured. `certbot renew --dry-run`. |
| high | Weak TLS cipher in use: ⟨cipher_name⟩ | Update the cipher suite. nginx: `ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:...`. See Mozilla SSL Configuration Generator (intermediate or modern profile). |
| high | Weak TLS protocol accepted: ⟨proto⟩ | Disable ⟨proto⟩ at the web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;` Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`. If behind a CDN, configure at the CDN edge. |
| medium | Deep TLS handshake failed | Verify the cert chain is valid and SNI works. |
| medium | TLS certificate expires in ⟨days⟩ days | Verify renewal is automated. Set a calendar reminder if not. |
| medium/info | ⟨title⟩ | Prefer AEAD ciphers (AES-GCM, CHACHA20-POLY1305). Nginx example: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384; ssl_prefer_server_ciphers on; |
| low | Certificate has no SubjectAltName (SAN) — modern browsers will reject | Reissue the certificate with a SAN list including every host you serve. |
| info | Certificate covers ⟨value⟩ SAN entries | No action needed. |
| info | Deep TLS audit skipped — site is not HTTPS | Serve the site over HTTPS first; then this check becomes meaningful. |

## Evidence the check records

- Deep TLS audit skipped — site is not HTTPS: target scheme: ⟨value⟩
- Deep TLS handshake failed: Connect/handshake to ⟨host⟩:⟨port⟩ failed: ⟨value⟩
- Self-signed certificate at ⟨host⟩: Subject CN = Issuer CN = ⟨value⟩. No trusted CA in the chain.
- Certificate has no SubjectAltName (SAN) — modern browsers will reject: Subject CN: ⟨value⟩, no SAN.
- Certificate covers ⟨value⟩ SAN entries: Sample SANs: ⟨value⟩
- Weak TLS protocol accepted: ⟨proto⟩: ⟨host⟩:⟨port⟩ ⟨msg⟩ Weak protocols banned by PCI-DSS 3.2.1 and most modern compliance regimes.
- Weak TLS cipher in use: ⟨cipher_name⟩: Negotiated cipher: ⟨cipher_name⟩ (⟨value⟩ bits)
- ⟨title⟩: Negotiated TLS: ⟨value⟩ Cipher: ⟨cipher_name⟩ Cipher bits: ⟨value⟩
- TLS certificate EXPIRED ⟨value⟩ days ago: notAfter: ⟨not_after⟩
- TLS certificate expires in ⟨days⟩ days: notAfter: ⟨not_after⟩; Subject CN: ⟨value⟩
- TLS certificate expires in ⟨days⟩ days: notAfter: ⟨not_after⟩; Subject CN: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(2)(i)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-13
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only tls_deep https://example.com
```

`only` runs this check alone and prints its findings.
