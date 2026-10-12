---
id: brand_monitor
title: "Typosquat-of-your-domain brand monitor (#170)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 57
---

# Typosquat-of-your-domain brand monitor (#170)

**check_id**: `brand_monitor`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1583.001 — Domains
**CWE**: CWE-441
**D3FEND**: D3-DNS

## What it does

Brand-monitor — flag typosquats of your domain.

Round-64 #170 — given the target domain `example.com`, generate
common typosquat permutations (`exampie.com`, `examp1e.com`,
`xn--exmple-...` etc.) and check whether they exist via DNS.

Limited to a curated permutation set to keep query count low. Skips
in CI / WPSECSCAN_NO_NETWORK mode.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ typosquat domain(s) registered against ⟨bare⟩ | Investigate each typosquat. If it hosts a phishing or copycat of your site: - File a UDRP complaint at WIPO - Notify your hosting + registrar - Add SPF/DMARC strict on your domain to reduce email-spoof risk Prophylactically: register the 5-10 most-obvious typosquats yourself + redirect to your real domain. |

## Evidence the check records

- ⟨count⟩ typosquat domain(s) registered against ⟨bare⟩: Registered typosquats: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: SC-20
- **compliance_map / iso_27001**: A.5.31

## Run only this check

```
wpsecscan only brand_monitor https://example.com
```

`only` runs this check alone and prints its findings.
