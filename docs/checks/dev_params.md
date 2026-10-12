---
id: dev_params
title: "Beta/test/debug query parameters"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 88
---

# Beta/test/debug query parameters

**check_id**: `dev_params`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-489
**D3FEND**: D3-SU

## What it does

Beta / test / debug parameter discovery.

Probes common 'unlock-the-hidden-feature' query parameters against the homepage.
A response that DIFFERS from the baseline indicates the parameter is consumed
somewhere in the code path — often by a forgotten debug toggle.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | Dev/test parameter consumed: ?⟨param⟩=⟨value⟩ (⟨label⟩) | Audit the plugin/theme that handles this parameter — production code shouldn't have an unauthenticated debug toggle. If it's WP_DEBUG bleeding into responses, set `define('WP_DEBUG_DISPLAY', false);` in wp-config.php. |
| info | Dev-parameter probe skipped — couldn't baseline / | No action. |
| info | No dev/test parameters consumed by the homepage | No action. |

## Evidence the check records

- Dev-parameter probe skipped — couldn't baseline /: GET / returned no body.
- No dev/test parameters consumed by the homepage: Probed ⟨count⟩ common dev toggles; none altered the response.
- Dev/test parameter consumed: ?⟨param⟩=⟨value⟩ (⟨label⟩): GET /?⟨param⟩=⟨value⟩ -&gt; HTTP ⟨status⟩ (body delta ⟨delta⟩ bytes vs baseline). Suspect: ⟨label⟩.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2.4
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only dev_params https://example.com
```

`only` runs this check alone and prints its findings.
