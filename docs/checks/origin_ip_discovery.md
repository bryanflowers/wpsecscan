# Origin-IP discovery via subdomains (#23)

**check_id**: `origin_ip_discovery`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — IP Addresses
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#23 Origin-IP discovery — find the un-CDN'd backend IP.

For Cloudflare/Fastly-fronted sites, the real origin IP is often discoverable
via:
  1. SSL Certificate Transparency logs (crt.sh search)
  2. DNS history (securitytrails / crt.sh)
  3. Sender IP in any auto-generated email
  4. Common subdomains that may not be CDN'd (mail.X, ftp.X, dev.X, staging.X)

We do (1) + (4) — the others need paid APIs.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only origin_ip_discovery
```
