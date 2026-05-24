# Plugin file-hash fingerprint (#2)

**check_id**: `plugin_hash_fingerprint`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software Discovery
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

#2 (from wpscan) — plugin file-hash → version fingerprinting.

When `readme.txt` is stripped (a common hardening step), the standard plugin
version-detection path fails. But static files (CSS / JS / image bundles)
usually still ship verbatim per plugin release. We hash those files and
match against a curated hash → version map.

Hash format: sha256(body_bytes), first 16 hex chars (64-bit) — enough to
avoid collisions for our purposes, short enough to keep the JSON small.

User can extend the shipped map via ~/.wpsecscan/plugin_hashes.json.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only plugin_hash_fingerprint
```
