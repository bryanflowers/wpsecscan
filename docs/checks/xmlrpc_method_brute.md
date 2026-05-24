# XML-RPC hidden-method brute-force (#8)

**check_id**: `xmlrpc_method_brute`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

#8 (from wpscan) — XML-RPC hidden-method brute-force.

`xmlrpc.php` lets plugins register custom methods alongside the WP-core
methods. `system.listMethods` usually returns them, but some plugins hide
methods from the listing while still exposing them. wpscan brute-forces
~200 method-name candidates to find these.

We send `<methodCall><methodName>X</methodName>...</methodCall>` for each
candidate name; a `faultCode -32601 "method does not exist"` means it
truly doesn't, any other response (auth required, malformed-params,
success) means the method IS registered.

Passive — single GET to confirm xmlrpc.php is enabled before brute-forcing.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only xmlrpc_method_brute
```
