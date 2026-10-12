---
id: cryptominer_js_injection
title: "Cryptominer JS injection (#56)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 56
---

# Cryptominer JS injection (#56)

**check_id**: `cryptominer_js_injection`
**aggressive**: no
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1496 — Resource Hijacking
**CWE**: CWE-94
**D3FEND**: D3-OE

## What it does

Cryptominer JS-injection detection on public pages.

Round-64 #56 — compromised WordPress sites are frequently used to host
crypto-mining JS (Coinhive, WebMiner, CryptoNight variants). The
homepage + a couple of common landing pages are scanned for the JS
fingerprints. Coinhive itself is dead since 2019, but its successors
and the same code-pattern keep cropping up in 2024+.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Cryptominer JS pattern detected on ⟨count⟩ page(s) | This is almost always a sign of site compromise. Steps: 1. Identify the injection point — grep theme + plugin PHP for `wp_enqueue_script` calls + suspicious base64. 2. Check wp_options for `siteurl` / `home` tampering. 3. Audit recent file modifications (`find wp-content -mtime -7`). 4. Restore from a known-clean backup. 5. Rotate admin passwords + WP salts. |

## Compliance mapping

- **compliance_map / pci_dss**: 11.5.1
- **compliance_map / nist_800_53**: SI-3
- **compliance_map / iso_27001**: A.8.7

## Run only this check

```
wpsecscan only cryptominer_js_injection https://example.com
```

`only` runs this check alone and prints its findings.
