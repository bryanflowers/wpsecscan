# HTTP/2 fingerprint + EOL backend

**check_id**: `http2_settings`
**aggressive**: no
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software

## What it does

HTTP/2 fingerprint check.

Looks at httpx-reported h2 negotiation + Server header to infer the backend
HTTP/2 stack. Modern nginx (>=1.13.10), Apache (mod_http2 >=2.4.26), litespeed,
and cloudflare each have distinctive `Server:` advertisements. Flags any
backend that's known to be EOL or has unpatched H/2 CVEs.

(httpx already negotiates h2 via the `http2=True` we pass to Client.)

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only http2_settings
```
