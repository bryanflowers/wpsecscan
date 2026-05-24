# XML-RPC method enumeration

**check_id**: `xmlrpc_deep`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.004 — Brute Force: Credential Stuffing

## What it does

Deep XML-RPC enumeration.

Beyond what login.py already checks, this:
  1. Lists every registered XML-RPC method via system.listMethods
  2. Flags dangerous combinations (pingback.ping + system.multicall = SSRF amplifier)
  3. Probes for the Akismet pingback validation bug pattern (CVE-2014 family)
  4. Checks if mt.supportedMethods / blogger.* endpoints are open (legacy editor protocols)

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only xmlrpc_deep
```
