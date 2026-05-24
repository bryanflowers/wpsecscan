# Apex vs www hostname collision

**check_id**: `hostname_collision`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1583.001 — Acquire Infrastructure: Domains
**CWE**: CWE-346
**D3FEND**: D3-DNSTI

## What it does

H8 Hostname collision detector.

If `www.target.com` and `target.com` resolve to different servers — or
serve different sites — that's almost always a config mistake. Worse: an
attacker who claims the apex (or vice-versa) can serve content under YOUR
brand. Also catches cases where `target.com` is parked while `www.` is the
real site (or vice-versa).

Compares the homepages of `apex` vs `www.apex`:
  - Same fingerprint (favicon hash, title, body length) → fine
  - Different status codes (one 200, other 404/30x to a parking page) → flagged
  - Different content → flagged as potential subdomain takeover

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only hostname_collision
```
