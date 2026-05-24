# Gutenberg block CVE scanner (#1)

**check_id**: `gutenberg_blocks`
**aggressive**: no
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

#1 Gutenberg block CVE scanner.

Third-party block plugins ship their own static assets at predictable
paths under /wp-content/plugins/<slug>/build/index.js — and many embed a
`version` field in the block.json that's served alongside. We scan for
known-vulnerable block packages.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only gutenberg_blocks
```
