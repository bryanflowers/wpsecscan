---
id: cache_poisoning_v2
title: "Cache poisoning chain v2 (#35)"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Transport & headers"
words: 126
---

# Cache poisoning chain v2 (#35)

**check_id**: `cache_poisoning_v2`
**aggressive**: yes
**category**: Transport & headers
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-444
**D3FEND**: D3-NTA

## What it does

#35 cache poisoning chain v2 — full poison-then-victim chain.

Sends two requests:
  1. Poison: GET / with X-Forwarded-Host: evil.example.com (asks cache to
     store a response whose internal links point at evil.example.com)
  2. Victim: GET / with a normal Host header — if the response contains
     evil.example.com, the cache served the poisoned copy.

Aggressive only.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Cache poisoned via X-Forwarded-Host → next visitor served attacker host | 1. Strip X-Forwarded-* / X-Host / Forwarded headers at the CDN edge. 2. Configure the application to use a hard-coded `WP_SITEURL` rather than `$_SERVER['HTTP_HOST']`. 3. Have the CDN include the rewritten host in the cache key, OR add Vary: X-Forwarded-Host to all responses. |
| info | Cache-poisoning v2 skipped (passive) | No action. |
| info | Cache-poisoning v2 — no marker in victim response | No action. |
| info | Cache-poisoning v2 — victim fetch failed | No action. |

## Evidence the check records

- Cache-poisoning v2 — no marker in victim response: The X-Forwarded-Host poison marker didn't reach the next visitor.
- Cache-poisoning v2 skipped (passive): Pass --aggressive.
- Cache-poisoning v2 — victim fetch failed: Could not retrieve /.
- Cache poisoned via X-Forwarded-Host → next visitor served attacker host: Phase 1 (poison): X-Forwarded-Host: ⟨poison_marker⟩ → cached. Phase 2 (victim, no header): response contained `⟨poison_marker⟩`. Attackers can redirect every cache-hit visitor to an arbitrary host.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only cache_poisoning_v2 https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
