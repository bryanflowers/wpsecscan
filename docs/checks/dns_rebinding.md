# DNS-rebinding SSRF probe

**check_id**: `dns_rebinding`
**aggressive**: yes
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1071.004 — Application Layer Protocol: DNS
**CWE**: CWE-350
**D3FEND**: D3-DNSTI

## What it does

H2 DNS-rebinding SSRF (passive guidance + active probe when possible).

DNS rebinding is when an attacker registers a domain whose first DNS lookup
returns the attacker's server (passes any allow-list) but the second lookup
returns 127.0.0.1 (after the allow-list check has already passed). If the
server fetches the URL twice (e.g. validation + retrieval), the second fetch
hits the internal host.

We can't fully test rebinding without a controlled DNS server, but we CAN:
  1. Use the public `*.rbndr.us` service (singe.id's rebinder), which returns
     alternating answers for `<first-ip>.<second-ip>.rbndr.us`.
  2. Build `7f000001.0a000001.rbndr.us` → resolves 127.0.0.1 / 10.0.0.1 alternately.

If the existing SSRF check found a confirmed parameter, we feed it a rebinder
URL and compare two consecutive responses. Mismatching body length is the
indicator of a successful rebind (the second fetch hit a different host).

Aggressive only.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only dns_rebinding
```
