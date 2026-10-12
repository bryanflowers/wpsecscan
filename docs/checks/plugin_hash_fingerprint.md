---
id: plugin_hash_fingerprint
title: "Plugin file-hash fingerprint (#2)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 178
---

# Plugin file-hash fingerprint (#2)

**check_id**: `plugin_hash_fingerprint`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: info
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Plugin file-hash fingerprint — no hash map loaded | No action. |
| info | Plugin file-hash fingerprint — no version matches (⟨matched_paths⟩ files fetched) | No action. |
| info | Plugin versions inferred from file hashes (⟨count⟩ match(es)) | If you stripped readme.txt to hide the version, also strip / fingerprint-bust the asset bundles — change a few bytes in the minified CSS so the hash differs. Or accept that obscurity isn't real defence and focus on patching to the latest. |

## Evidence the check records

- Plugin versions inferred from file hashes (⟨count⟩ match(es)): ⟨value⟩ This works even when readme.txt has been removed for hardening. The version informs subsequent CVE matching.
- Plugin file-hash fingerprint — no hash map loaded: Built-in map empty + no ~/.wpsecscan/plugin_hashes.json. Drop a JSON to extend.
- Plugin file-hash fingerprint — no version matches (⟨matched_paths⟩ files fetched): Hashed every reachable plugin file in the map; none matched a known release. Either every installed plugin is custom-built / private, or all are at versions newer than the shipped map. Consider contributing your release hashes back upstream.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only plugin_hash_fingerprint https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
