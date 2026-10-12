---
id: host_platform_detect
title: "Host stack / platform fingerprint (N136/N139/N140)"
severity_max: info
severity_dynamic: true
aggressive: false
category: "DNS, email & infra"
words: 101
---

# Host stack / platform fingerprint (N136/N139/N140)

**check_id**: `host_platform_detect`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: info (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

N136 + N139 + N140 (v2.6.0) — host / stack fingerprint with
platform-specific advisories.

Detects:
  • Roots stack (Bedrock / Sage / Trellis / Sail)
  • WordPress VIP (Go)
  • WP Engine, Kinsta, Pantheon, Cloudways

For each detected host, emits an info-level "platform detected" entry
plus host-specific medium advisories where one applies (e.g. WP-VIP
enforces some controls in its own ingress that other hosts don't;
operators sometimes layer duplicate / conflicting protections on top).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Host / stack detected: ⟨platform⟩ | Confirm the platform-managed controls and suppress duplicate checks in ~/.wpsecscan/policy.yml if appropriate. |
| varies | ⟨platform⟩ ⟨suffix⟩ | — |

## Evidence the check records

- Host / stack detected: ⟨platform⟩: Platform fingerprint: ⟨platform⟩. wpsecscan's check defaults are tuned for vanilla shared-hosting WordPress; host-specific advice follows.
- ⟨platform⟩ ⟨suffix⟩: Platform: ⟨platform⟩. ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only host_platform_detect https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
