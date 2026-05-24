# Favicon fingerprint

**check_id**: `favicon_fingerprint`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Favicon-fingerprint check.

Hash the favicon and report it. Useful for two reasons:
  1. Threat-intel feeds (Shodan, Censys) index sites by favicon hash —
     yours being indexable means it's findable by attackers searching for
     specific stacks.
  2. Default-favicon collisions tell you the site is "stock" (no branding
     in place), which often correlates with overall security posture.

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1

## Run only this check

```
wpsecscan --target https://example.com --only favicon_fingerprint
```
