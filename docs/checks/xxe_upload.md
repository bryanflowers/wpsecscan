# XXE via SVG upload probe

**check_id**: `xxe_upload`
**aggressive**: yes
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only xxe_upload
```
