---
id: secret_leak
title: "Accidental API-key leak scan"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "File & directory exposure"
words: 106
---

# Accidental API-key leak scan

**check_id**: `secret_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Unsecured Credentials: Credentials in Files

## What it does

Accidental secret-leak detection.

Scans page bodies for patterns that look like API keys / tokens left in
the HTML or in JS files. WordPress sites frequently leak Stripe keys,
Google Maps API keys, Mailchimp keys, etc. when developers build client-side
configs directly into the page.

Detection is regex-based; we redact the matched value before placing it in
the finding so the report itself doesn't leak the secret.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low) | ⟨name⟩ present in page source | 1. Rotate the ⟨value⟩ IMMEDIATELY at the provider — assume the original is compromised. 2. Move the secret out of client-side code. Sensitive ops should be proxied through a server-side endpoint that holds the secret on the server. 3. Audit access/billing logs for unauthorized use. |
| info | No accidental secret patterns detected | No action needed. |

## Evidence the check records

- ⟨name⟩ present in page source: Discovered at: ⟨path⟩ Value (redacted): ⟨redacted⟩ Secrets in HTML/JS responses are visible to every site visitor and search engine.
- No accidental secret patterns detected: Scanned ⟨count⟩ response bodies against ⟨count⟩ secret patterns.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/ | grep -oE 'sk_live_[A-Za-z0-9]+'
curl -s https://example.com/ | grep -oE 'AKIA[A-Z0-9]{16}'
# TruffleHog scans web assets for secrets:
trufflehog url https://example.com
```

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: IA-5
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.a
- **compliance_v2 / cmmc**: IA.L2-3.5.10
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.10

## References

- primary: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- https://[a-f0-9

## Run only this check

```
wpsecscan only secret_leak https://example.com
```

`only` runs this check alone and prints its findings.
