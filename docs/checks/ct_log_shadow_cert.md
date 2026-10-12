---
id: ct_log_shadow_cert
title: "CT-log shadow certificate detection (A31)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 138
---

# CT-log shadow certificate detection (A31)

**check_id**: `ct_log_shadow_cert`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1556.004 — Network Provider MITM
**CWE**: CWE-295
**D3FEND**: D3-CRO

## What it does

A31 (v2.6.0) — Certificate Transparency log shadow-cert.

Sibling of the existing `ct_log_recent_certs` check, but tighter:
specifically flag certificates issued for the apex domain by a CA
whose name doesn't match the CA on the LIVE cert. If the live site
uses Let's Encrypt and the CT log shows a recent Sectigo or GoGetSSL
cert for the same apex, that's a strong signal of a shadow-cert
attack (attacker registered a cert behind the operator's back).

Uses crt.sh (free CT-log search) for the lookup.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | CT log shows a non-live-issuer cert for ⟨host⟩: ⟨value⟩ | 1. Verify whether YOU issued this cert (CDN, separate email/DNS provider, an old monitoring tool). 2. If not, treat as a serious incident: rotate DNS API credentials NOW; audit DNS records for unauthorised _acme-challenge TXT records. 3. Add the apex to a CAA record naming ONLY your real CA (e.g. `example.com. CAA 0 issue "letsencrypt.org"`). 4. Subscribe to crt.sh email notifications for the apex. |

## Evidence the check records

- CT log shows a non-live-issuer cert for ⟨host⟩: ⟨value⟩: Live site cert: issuer = ⟨live_issuer⟩ CT-log entry shows a separate cert issued by: ⟨issuer⟩ Issuance dates: ⟨value⟩ A foreign-CA cert on the same apex is a shadow-cert signal (an attacker may have completed domain validation behind your back, perhaps via a stolen DNS API key).

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## References

- https://crt.sh/?q=

## Run only this check

```
wpsecscan only ct_log_shadow_cert https://example.com
```

`only` runs this check alone and prints its findings.
