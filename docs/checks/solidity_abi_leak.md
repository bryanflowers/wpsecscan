---
id: solidity_abi_leak
title: "Solidity contract ABI leak (#74)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 93
---

# Solidity contract ABI leak (#74)

**check_id**: `solidity_abi_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-538
**D3FEND**: D3-NTA

## What it does

Solidity contract ABI leak detection.

Round-64 #74 — Web3 plugins that interact with a custom Solidity
contract usually need the contract's ABI (Application Binary Interface)
on the client side to call methods. The ABI itself isn't secret, but its
location often reveals: (a) the contract address (good for tracking
attacks), (b) admin-only methods (an attacker now knows what privileged
calls exist), (c) sometimes the SOURCE code in a comment block.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | Solidity contract ABI exposed at ⟨path⟩ | Move the ABI out of /wp-content/uploads (which is world-readable) into a non-public dir, or ship it bundled in the plugin JS (so the URL fingerprint doesn't reveal the contract location). If source code is embedded, strip artifacts down to ABI-only before publishing. |

## Evidence the check records

- Solidity contract ABI exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes) Admin-like methods: ⟨value⟩ Source code embedded: yes Directory listing: yes

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only solidity_abi_leak https://example.com
```

`only` runs this check alone and prints its findings.
