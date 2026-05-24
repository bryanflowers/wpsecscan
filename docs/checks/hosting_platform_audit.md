# WP Engine/Kinsta/CF/Amplify audits (#16-22)

**check_id**: `hosting_platform_audit`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#16-22 — Cloud / hosting-platform audits in one module.

#16 WP Engine hardening (extends existing wp_engine_misconfig with 2026-vintage paths)
#17 Kinsta / Pressable / Pantheon fingerprint + known-issue checks
#18 Cloudflare API-token / R2 / Workers leak scan
#19 AWS Amplify build-config leak
#20 Heroku / Render / Fly.io free-tier WP fingerprint
#21 GitHub Pages WP-mirror detection
#22 CDN cache-key confusion probe

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only hosting_platform_audit
```
