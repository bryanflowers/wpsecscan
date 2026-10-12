---
id: xxe_upload
title: "XXE via SVG upload probe"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 183
---

# XXE via SVG upload probe

**check_id**: `xxe_upload`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-611
**D3FEND**: D3-IAA

## What it does

XXE via SVG upload probe.

WordPress sites accept SVG uploads via Contact Form 7, Forminator, Gravity Forms,
Ninja Forms, WooCommerce product images, and many others. SVG is XML — so a
DOCTYPE entity reference can:
  - Read local files (file:///etc/passwd via &xxe;)
  - SSRF to internal IPs / cloud metadata
  - Billion-laughs DoS

We probe by sending a BENIGN SVG that includes a DOCTYPE entity reference to a
canary domain. If the response reflects the entity content or our request takes
suspiciously long (entity expansion), the parser is XXE-vulnerable.

Aggressive-only (sends a small file upload).

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | XXE candidate at ⟨path⟩ | Disable DOCTYPE in the SVG parser. The plugin owning this endpoint should use `libxml_disable_entity_loader(true)` (PHP &lt;8) or pass `LIBXML_NONET \| LIBXML_NOENT` to its XML parser. For PHP 8+, the loader is disabled by default — confirm the plugin isn't manually re-enabling it. |
| info | No known WP form upload endpoints reachable — XXE probe skipped | No action. |
| info | XXE / SVG upload probe clean | No action. |
| info | XXE / SVG upload probe skipped (requires --aggressive) | No action. |

## Evidence the check records

- XXE / SVG upload probe skipped (requires --aggressive): This probe POSTs a small SVG containing a DOCTYPE entity reference.
- No known WP form upload endpoints reachable — XXE probe skipped: None of the ⟨count⟩ known WP form upload AJAX paths responded.
- XXE / SVG upload probe clean: Tested ⟨value⟩ reachable upload endpoint(s); no entity-resolution indicators.
- XXE candidate at ⟨path⟩: POSTed an SVG containing `<!ENTITY xxe SYSTEM "http://⟨canary⟩.example.invalid/...">` Indicator: ⟨why⟩ A confirming attacker can change the entity URL to file:///etc/passwd, http://169.254.169.254/latest/meta-data/, or a billion-laughs payload.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- deep dive: https://portswigger.net/web-security/xxe

## Run only this check

```
wpsecscan only xxe_upload https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
