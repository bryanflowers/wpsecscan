---
id: timthumb
title: "timthumb.php CVE detection (#1)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 108
---

# timthumb.php CVE detection (#1)

**check_id**: `timthumb`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

#1 (from wpscan) — timthumb.php detection + version-banner CVE matching.

timthumb is a long-deprecated image-thumbnail PHP library shipped with many
old free WordPress themes. Versions before 2.8.14 had remote-file-include
bugs (CVE-2011-4106, CVE-2014-4663) that gave attackers RCE. Despite being
patched in 2014, it's still found on ~3-5% of WP sites in the wild because
the theme bundles haven't been updated.

We probe 8 common timthumb paths and inspect the banner comment for the
version string.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/low/info | ⟨title⟩ | Remove timthumb.php — it's been obsolete since 2014 and built-in WP image functions (`wp_get_attachment_image_src` + the media library) cover every use case. If the theme depends on it, switch to a modern theme. |
| info | No timthumb.php found | No action. |

## Evidence the check records

- No timthumb.php found: Probed ⟨count⟩ common timthumb paths; none returned a timthumb-shaped response.
- ⟨title⟩: GET ⟨path⟩ -&gt; 200 OK, body contains a timthumb banner; version ⟨version⟩ / ; no version string detected.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only timthumb https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
