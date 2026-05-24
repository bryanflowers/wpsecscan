# WP-CLI command-injection probe (#B28)

**check_id**: `wp_cli_inject`
**aggressive**: yes
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
wpsecscan --target https://example.com --only wp_cli_inject
```
