# ACF/MS/agent/child/WP-CLI audit (#11-15)

**check_id**: `plugin_specific_audit`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#10-15 — Plugin-specific deep audits in one module.

#10 Gravity Forms file-upload MIME-confusion probe (aggressive)
#11 ACF Pro license JWT leak scan
#12 Multisite tenant-isolation probe
#13 ManageWP / MainWP / iThemes Sync agent detection
#14 Child-theme override fingerprint
#15 WP-CLI exposure (`/wp-cli.phar`, command-passthrough hacks)

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only plugin_specific_audit
```
