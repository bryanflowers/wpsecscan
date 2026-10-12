---
id: page_builder_cve
title: "Page-builder fingerprint + known-CVE family hint"
severity_max: low
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 159
---

# Page-builder fingerprint + known-CVE family hint

**check_id**: `page_builder_cve`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: low
**OWASP**: A06:2021 — Vulnerable and Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-1395
**D3FEND**: D3-SVCDM

## What it does

Item #18 — fingerprint page-builders + cross-reference known CVE families.

The popular WordPress page-builders share a pattern: they expose front-end
HTML markers, ship deep frontend JS APIs, and each has had at least one
critical RCE (Bricks CVE-2024-25600 unauth RCE; Beaver had a 2023 stored-
XSS family; Divi had the et_pb_send_to_friend RCE in 2024; WPBakery had
multiple stored-XSS issues).

This check is detection-only. We fingerprint via HTML markers and report
the builder + a hint at currently-known CVE families. We deliberately do
NOT version-detect or fire an exploit — the `plugin_cves` check pulls
the canonical CVE feed; we just make sure these builders are visible to
that pipeline even when they're served by a theme (Bricks, Divi) rather
than installed as a plugin.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Page builder detected: ⟨name⟩ | Verify ⟨name⟩ is fully patched. Cross-reference the running version against wpscan.com / patchstack.com — `wpsecscan` pulls these into the plugin_cves check when a version string is visible. If only a theme-bundled builder (Bricks or Divi), check the theme version explicitly: WP admin → Appearance → Themes → click the active theme. |
| info | Page-builder fingerprint — none detected | No action needed. |

## Evidence the check records

- Page-builder fingerprint — none detected: Scanned / for markers from ⟨count⟩ known builders.
- Page builder detected: ⟨name⟩: HTML markers consistent with ⟨name⟩ are present on the homepage. Known CVE families to verify against: ⟨cves⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only page_builder_cve https://example.com
```

`only` runs this check alone and prints its findings.
