---
id: waf_lockout_guard
title: "Early-abort guard: avoid IP-ban escalation when WAF blocks the first probe"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Other"
words: 248
---

# Early-abort guard: avoid IP-ban escalation when WAF blocks the first probe

**check_id**: `waf_lockout_guard`
**aggressive**: no
**category**: Other
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-693
**D3FEND**: D3-DR

## What it does

Item #42 — early-abort guard against bricking the client's site.

Some WAFs (Wordfence, Sucuri, Cloudflare with strict rules, plus Cloudways'
own lockout system) auto-ban scanning IPs after a single block-event. If a
full scan continues after the first 403, it can result in the operator's IP
being added to a permanent blocklist — meaning the operator can no longer
visit the client's WordPress admin from their normal network.

This check runs early in the scan order and sends one benign probe at a
URL that should always succeed: `/?_wpsec_test=1` plus a HEAD on the
homepage. If either returns 403/406/418/429 or a body that contains the
classic WAF block markers ("access denied", "you have been blocked",
"banned", "ray id" alongside Cloudflare branding), it sets
`ctx['shared']['waf_lockout'] = True` and emits a critical finding so
later checks can short-circuit.

The scanner runtime should honour this flag and stop scanning. The
finding is emitted regardless, so the user knows why the scan was
truncated.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WAF lockout — scan aborted to avoid IP-ban escalation | 1. Whitelist your scanner IP in the WAF (Wordfence/Sucuri/CF). Coordinate with the client BEFORE retrying — typically a 30-min temporary IP allow-list under WAF Settings. 2. Then re-run wpsecscan from the whitelisted IP. 3. If the lockout came from Cloudways' own platform-level limiter (not Wordfence), file a support ticket asking them to temporarily exempt your IP — they will not whitelist passive scanners but they will pause a temporary ban. |
| info | WAF lockout guard — no block detected on initial probe | No action needed. |

## Evidence the check records

- WAF lockout — scan aborted to avoid IP-ban escalation: The site WAF blocked the very first probe (⟨reason⟩). Continuing a 200-request scan against a WAF that's already actively blocking can escalate to a permanent IP-ban — which would lock the operator out of the client's admin interface from this network indefinitely. The scanner has set ctx['shared']['waf_lockout'] = True; subsequent checks should honour it and short-circuit.
- WAF lockout guard — no block detected on initial probe: HEAD / returned a non-blocking response. Continuing with the full scan.

## Compliance mapping

- **compliance_map / pci_dss**: 12.10.1
- **compliance_map / nist_800_53**: IR-4
- **compliance_map / iso_27001**: A.5.24

## Run only this check

```
wpsecscan only waf_lockout_guard https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
