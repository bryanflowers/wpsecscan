---
id: dns_rebinding
title: "DNS-rebinding SSRF probe"
severity_max: high
severity_dynamic: false
aggressive: true
category: "SSRF / RCE / open access"
words: 260
---

# DNS-rebinding SSRF probe

**check_id**: `dns_rebinding`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: high
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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Possible DNS-rebinding SSRF — two consecutive fetches returned different bodies | Resolve the hostname ONCE, validate the IP against an allow-list, then fetch by IP (with Host header). Or use a proven library: SafeURL, ssrf-shield, etc. |
| info | DNS-rebinding SSRF chain skipped (no SSRF candidate) | No action. |
| info | DNS-rebinding SSRF chain skipped (passive mode) | No action. |
| info | DNS-rebinding probe couldn't reach the rebinder | No action. |
| info | DNS-rebinding probe — bodies match across two fetches | No action. |

## Evidence the check records

- DNS-rebinding SSRF chain skipped (passive mode): Pass --aggressive AND have a confirmed SSRF candidate.
- DNS-rebinding SSRF chain skipped (no SSRF candidate): Needs the ssrf check to have confirmed a fetch-attacker-URL parameter first.
- DNS-rebinding probe couldn't reach the rebinder: rbndr.us was unreachable — try again from a network with outbound DNS.
- Possible DNS-rebinding SSRF — two consecutive fetches returned different bodies: Same probe URL ⟨probe⟩ returned ⟨len1⟩ bytes on call 1, ⟨len2⟩ on call 2. rbndr.us alternates between 127.0.0.1 and 10.0.0.1 across DNS responses; the second fetch likely hit a different host, which is the DNS-rebinding bypass pattern.
- DNS-rebinding probe — bodies match across two fetches: Both fetches returned ~⟨len1⟩ bytes. Not conclusive proof of safety, but no rebind observed.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## References

- primary: https://en.wikipedia.org/wiki/DNS_rebinding
- deep dive: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#bypass-via-open-redirect

## Run only this check

```
wpsecscan only dns_rebinding https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
