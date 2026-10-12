---
id: php_eol
title: "PHP end-of-life audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Other"
words: 107
---

# PHP end-of-life audit

**check_id**: `php_eol`
**aggressive**: no
**category**: Other
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

PHP version EOL audit.

Many WordPress sites silently run PHP versions that haven't received a
security patch in years. PHP's annual minor-release schedule means version
N is fully supported for 2 years, then receives security-only fixes for
1 more year — so anything older than ~3 years past its release date is
unsupported. Cross-references the detected PHP version against the
PHP-team's published end-of-life schedule.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low | PHP ⟨php⟩ ⟨suffix⟩ | Upgrade to a supported PHP version (8.2+ as of 2026). Most managed WordPress hosts let you switch in the control panel; self-hosted sites need an OS package update + a PHP-FPM/Apache module swap. Verify your plugins/themes claim compatibility with the target version before flipping the switch in production. |
| info | PHP version not disclosed in response headers | No action — this is the safe configuration. |
| info | PHP ⟨php⟩ appears to be a supported release | No action — but verify against https://www.php.net/supported-versions.php. |

## Evidence the check records

- PHP ⟨php⟩ ⟨suffix⟩: ⟨detail⟩ Detected via: ⟨value⟩
- PHP version not disclosed in response headers: Neither `Server` nor `X-Powered-By` revealed a PHP X.Y version.
- PHP ⟨php⟩ appears to be a supported release: Detected via response header; latest EOL data through 8.4.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.i
- **compliance_v2 / cmmc**: RA.L2-3.11.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## References

- https://www.php.net/supported-versions.php

## Run only this check

```
wpsecscan only php_eol https://example.com
```

`only` runs this check alone and prints its findings.
