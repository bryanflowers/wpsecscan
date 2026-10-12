---
id: magecart_skimmer_patterns
title: "Magecart / card-skimmer DOM hooks (#57)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 53
---

# Magecart / card-skimmer DOM hooks (#57)

**check_id**: `magecart_skimmer_patterns`
**aggressive**: no
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1056.003 — Web Portal Capture
**CWE**: CWE-79
**D3FEND**: D3-OE

## What it does

Magecart / payment-form skimmer detection.

Round-64 #57 — WooCommerce + EDD checkout pages are a frequent target
for JS skimmers that exfiltrate card numbers to attacker-controlled
domains. This check fetches a small set of checkout-shaped paths and
scans for known skimmer DOM hooks + the canonical "outbound POST to a
non-payment-processor domain" pattern.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Magecart-style skimmer pattern detected (⟨count⟩ hit) | Treat as live card-data exfiltration. Steps (PCI-mandated): 1. Take the site offline or short-circuit checkout while you investigate. 2. Notify your acquiring bank within 24 hours. 3. Engage a PFI (PCI Forensic Investigator) if you process &gt; 1k transactions/month. 4. Audit recent file modifications + plugin updates + admin user list. 5. Restore from a known-clean backup; rotate all secrets. |

## Compliance mapping

- **compliance_map / pci_dss**: 11.6.1
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.7

## Run only this check

```
wpsecscan only magecart_skimmer_patterns https://example.com
```

`only` runs this check alone and prints its findings.
