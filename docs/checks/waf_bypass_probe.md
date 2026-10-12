---
id: waf_bypass_probe
title: "WAF bypass/passthrough probe"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "WordPress core, plugins & themes"
words: 183
---

# WAF bypass/passthrough probe

**check_id**: `waf_bypass_probe`
**aggressive**: yes
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WAF bypass / passthrough probe.

After the `waf` check has detected a WAF, this probes whether it actually
FILTERS or just fingerprints. We send a benign-looking but WAF-trigger string
in a query parameter and compare the response against a control.

If the WAF blocks: status 403/406/501 or response body wildly different.
If the WAF passes the trigger through: same response shape as control → flag.

Aggressive-only (sends a `<script>` token).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WAF (⟨value⟩) passes ⟨count⟩ bypass payload(s) through | Verify the WAF ruleset has OWASP CRS Core (or the equivalent on your CDN) enabled. Cloudflare: 'Managed Rules' under Security; AWS WAF: managed rule group `AWSManagedRulesCommonRuleSet`; Wordfence (host-side): turn on extended protection mode. |
| info | WAF (⟨value⟩) blocks all ⟨count⟩ bypass probes | No action — WAF is filtering as expected. |
| info | WAF bypass probe skipped (requires --aggressive) | No action. |
| info | WAF bypass probe skipped — no WAF detected | No action. |
| info | WAF bypass probe — control request failed | No action. |

## Evidence the check records

- WAF bypass probe skipped (requires --aggressive): This check sends known-evil-looking query strings to test if your WAF filters them.
- WAF bypass probe skipped — no WAF detected: The `waf` check didn't fingerprint a WAF; nothing to test bypass against.
- WAF bypass probe — control request failed: Couldn't establish a control response; aborting.
- WAF (⟨value⟩) blocks all ⟨count⟩ bypass probes: Blocked: ⟨value⟩
- WAF (⟨value⟩) passes ⟨count⟩ bypass payload(s) through: Payloads that the WAF allowed (same response shape as control): ⟨value⟩ This doesn't mean the underlying app is vulnerable — just that the WAF isn't filtering these payload classes. The aggressive `sqli` / `xss_reflected` checks will exercise the actual app.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.16
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## References

- primary: https://portswigger.net/web-security/ssrf/bypassing-ssrf-filters

## Run only this check

```
wpsecscan only waf_bypass_probe https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
