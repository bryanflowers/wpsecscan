# Redirect chain analysis

**check_id**: `redirect_chain`
**aggressive**: no
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1071.001 — Application Layer Protocol: Web Protocols

## What it does

Redirect-chain analysis.

Follows redirects from / and /wp-admin/ up to 8 hops, recording every Location.
Flags:
  - Chains that bounce off-domain (potential session-cookie leak / XSS via Location)
  - Chains with HTTP→HTTPS→HTTP downgrades (mixed-content / cookie leak)
  - Excessive redirect count (>5 hops on the homepage = misconfigured)

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only redirect_chain
```
