---
id: wp_cli_inject
title: "WP-CLI command-injection probe (#B28)"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "WordPress core, plugins & themes"
words: 108
---

# WP-CLI command-injection probe (#B28)

**check_id**: `wp_cli_inject`
**aggressive**: yes
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059 — Command and Scripting Interpreter
**CWE**: CWE-78
**D3FEND**: D3-IVA

## What it does

Round-62 #B28 — WP-CLI command-injection probe (companion-plugin-driven).

The vast majority of "WP-CLI in webroot" vulnerabilities are NOT WP-CLI
itself — they're plugins / themes that shell-out to wp-cli with
user-supplied data interpolated into the command string. This check:

  1. Skips entirely if the companion plugin isn't available (we can't
     enumerate `add_action` callbacks from outside).
  2. Otherwise probes for /wp-cli.phar, /?wp_cli=info, common
     command-shell-via-plugin paths.
  3. Reports any 200 OK on those paths as critical.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WP-CLI artefact reachable: ⟨p⟩ | Delete ⟨p⟩. wp-cli should NEVER live in the document root — install globally via composer and keep it outside the public path. |
| high | Plugins with shell-exec names installed: ⟨count⟩ | Audit these plugins — names suggest they expose `passthru`/`system` to admin actions. Confirm capability checks + input sanitisation on every action. |
| info | WP-CLI inject probe — no exposed artefacts | No action. |

## Evidence the check records

- WP-CLI inject probe — no exposed artefacts: Probed ⟨count⟩ known wp-cli artefact paths.
- WP-CLI artefact reachable: ⟨p⟩: HEAD ⟨p⟩ -&gt; 200. wp-cli.phar in the webroot = full RCE if PHP exec is on.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan only wp_cli_inject https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
