---
id: waf_ruleset
title: "WAF rule-set identification"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 142
---

# WAF rule-set identification

**check_id**: `waf_ruleset`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WAF detected (⟨value⟩) but ruleset appears weak | Your WAF detection might just be a CDN's bot-management layer, not an actual application-layer ruleset. Enable a real WAF ruleset: Cloudflare Managed Rules, AWS WAF Core, ModSecurity OWASP CRS, or Wordfence Premium. |
| low/info | WAF ruleset fingerprint: ⟨value⟩; block rate ⟨block_rate⟩ | Your WAF is filtering OWASP-class attacks. Consider also: - Rate limiting on /wp-login.php (often a separate config) - Custom rules for plugins with known CVEs while waiting for patch |
| info | WAF ruleset fingerprint skipped — no WAF detected | No action. |

## Evidence the check records

- WAF ruleset fingerprint skipped — no WAF detected: The `waf` check didn't fingerprint a WAF vendor.
- WAF detected (⟨value⟩) but ruleset appears weak: Blocked ⟨value⟩/⟨value⟩ test payloads (block rate ⟨block_rate⟩). No fingerprintable strong ruleset (OWASP CRS, ModSecurity) in response bodies.
- WAF ruleset fingerprint: ⟨value⟩; block rate ⟨block_rate⟩: WAF vendors detected (from `waf` check): ⟨value⟩ Identified rulesets: ⟨value⟩ Blocked ⟨value⟩/⟨value⟩ probes.

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
wpsecscan only waf_ruleset https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
