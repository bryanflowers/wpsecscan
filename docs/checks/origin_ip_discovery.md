---
id: origin_ip_discovery
title: "Origin-IP discovery via subdomains (#23)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 128
---

# Origin-IP discovery via subdomains (#23)

**check_id**: `origin_ip_discovery`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
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

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Likely origin IP exposed via ⟨count⟩ subdomain(s) | Move every public-facing subdomain behind the same CDN/WAF. For mail/SMTP, use a separate dedicated hostname like mx.example.com that has its OWN strict firewall (only port 25/465/587, only inbound from MX-listed IPs). |
| info | Origin-IP discovery skipped | No action. |
| info | Origin-IP discovery: no non-CDN subdomain leak (⟨count⟩ subs probed) | No action — origin is well-hidden behind the CDN. |

## Evidence the check records

- Likely origin IP exposed via ⟨count⟩ subdomain(s): ⟨value⟩ CDN IP for ⟨host⟩: ⟨value⟩ The IPs above are NOT in known CDN ranges — an attacker can scan them directly, bypassing the WAF/CDN.
- Origin-IP discovery skipped: Host ⟨host⟩ unusable.
- Origin-IP discovery: no non-CDN subdomain leak (⟨count⟩ subs probed): All resolved subdomains either match the CDN IP ⟨cdn_ip⟩ or are in known CDN ranges.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan only origin_ip_discovery https://example.com
```

`only` runs this check alone and prints its findings.
