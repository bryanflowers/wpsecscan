# HTTP Parameter Pollution probe

**check_id**: `hpp`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-235
**D3FEND**: D3-IVA

## What it does

H6 HTTP Parameter Pollution (HPP).

Sending duplicate query parameters can confuse servers that don't normalise:
  ?id=1&id=2  → backend reads `id=1`, WAF reads `id=2`, etc.
This is the classic technique for evading allow-list-based WAFs and for
triggering uncommon code paths in plugins that handle their own parameter
parsing.

We probe a few common endpoints with both `?id=normal` and `?id=normal&id=evil`
and look for behaviour differences (status code, body length, or `WAF blocked`
markers appearing in only one variant).

Aggressive only — the duplicate-param payloads include reserved values
(`<script>`, etc.) that some WAFs interpret as attacks.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only hpp
```
