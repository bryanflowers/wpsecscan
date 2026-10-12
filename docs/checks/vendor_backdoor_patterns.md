---
id: vendor_backdoor_patterns
title: "Known-bad / vendor-backdoor plugin slugs (#55)"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 86
---

# Known-bad / vendor-backdoor plugin slugs (#55)

**check_id**: `vendor_backdoor_patterns`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain
**CWE**: CWE-506
**D3FEND**: D3-SCM

## What it does

Detect plugin slugs from a curated known-bad / vendor-backdoor list.

Round-64 #55 — there is a small but real set of WP plugins that have
either (a) historically shipped with backdoors, (b) been bought by
malicious actors who then injected them, or (c) are clones of pirated
premium plugins (a classic webshell-delivery vector). This check
fingerprints each by /wp-content/plugins/&lt;slug&gt;/ readme.txt existence.
The list is intentionally small + conservative to keep false-positive
risk low.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, info) | High-risk plugin detected: ⟨slug⟩ | Uninstall ⟨slug⟩ immediately if not strictly required. If you need this functionality, switch to a maintained alternative. If it's a pirated-premium clone ("-nulled"), assume your site is already compromised — restore from a known-clean backup, rotate all admin credentials + salts, scan for added admin users + database triggers. |

## Evidence the check records

- High-risk plugin detected: ⟨slug⟩: GET /wp-content/plugins/⟨slug⟩/readme.txt -&gt; 200 (⟨count⟩ bytes) Reason: ⟨reason⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SA-12
- **compliance_map / iso_27001**: A.8.30

## Run only this check

```
wpsecscan only vendor_backdoor_patterns https://example.com
```

`only` runs this check alone and prints its findings.
