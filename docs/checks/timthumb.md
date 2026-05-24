# timthumb.php CVE detection (#1)

**check_id**: `timthumb`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only timthumb
```
