# WAF rule-set identification

**check_id**: `waf_ruleset`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

WAF rule-set fingerprinting.

Once the `waf` check has identified a WAF vendor (Cloudflare, AWS WAF,
Sucuri, Wordfence), this check sends a small differential battery to identify
which RULESET is active:
  - OWASP CRS 3.x vs 4.x (different blocking thresholds)
  - Cloudflare Managed Ruleset vs Custom (paranoia level)
  - AWS WAF Common vs Bot Control
  - Wordfence Premium vs Free (different rule counts)

Identification is informational; tells the user *what* protection is actually
running, not just *that* a WAF exists.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only waf_ruleset
```
