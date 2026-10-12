---
id: gutenberg_blocks
title: "Gutenberg block CVE scanner (#1)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 52
---

# Gutenberg block CVE scanner (#1)

**check_id**: `gutenberg_blocks`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: info
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

#1 Gutenberg block CVE scanner.

Third-party block plugins ship their own static assets at predictable
paths under /wp-content/plugins/&lt;slug&gt;/build/index.js — and many embed a
`version` field in the block.json that's served alongside. We scan for
known-vulnerable block packages.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Gutenberg block scan — no known third-party blocks detected | No action. |
| info | Gutenberg blocks detected: ⟨count⟩ | Cross-reference each version against the plugin's CVE history. Some third-party blocks have had stored-XSS issues in their `save()` markup. |

## Evidence the check records

- Gutenberg block scan — no known third-party blocks detected: Probed ⟨count⟩ known block plugins.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only gutenberg_blocks https://example.com
```

`only` runs this check alone and prints its findings.
