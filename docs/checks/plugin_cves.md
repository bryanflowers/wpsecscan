---
id: plugin_cves
title: "Plugin CVE matching"
severity_max: high
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 136
---

# Plugin CVE matching

**check_id**: `plugin_cves`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high (some findings take their severity at run time)
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Plugin CVE matching against the Wordfence Intelligence DB.

Uses plugin versions discovered by the `plugins` check (ctx['shared']['plugins']).
When aggressive mode is on, also runs confirmed-exploit signatures from
data/exploit_signatures.json against matching plugins.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WPScan: ⟨slug⟩ v⟨ver⟩ — ⟨value⟩ | Update '⟨slug⟩' to ⟨value⟩. |
| low | Plugin '⟨slug⟩' exists in CVE database but version not detected | Manually verify the version of '⟨slug⟩' from Dashboard → Plugins. Update to the latest release. |
| info | No known-vulnerable plugin versions detected among ⟨count⟩ plugin(s) | No action needed. Keep all plugins updated — coverage depends on detected versions. |
| info | No plugins to cross-reference against CVE database | If you know plugins are installed, run against a page that loads them. |
| info | Vulnerability database is empty | Run `wpsecscan --update-db` (CLI) or click 'Refresh DB' in the GUI to download Wordfence Intelligence. |
| info | WPScan API lookup failed | Verify --wpscan-token and remaining quota (free tier: 25 req/day). |
| varies | Known vulnerability in ⟨slug⟩ ⟨value⟩: ⟨value⟩ | — |
| varies | [CONFIRMED] ⟨value⟩ | — |

## Evidence the check records

- Vulnerability database is empty: No cached or embedded vulnerability database found.
- No plugins to cross-reference against CVE database: ⟨db_note⟩. Plugin enumeration found no slugs.
- No known-vulnerable plugin versions detected among ⟨count⟩ plugin(s): ⟨db_note⟩.
- [CONFIRMED] ⟨value⟩: Signature: ⟨sig_id⟩ Probe: ⟨value⟩ ⟨value⟩ Match: ⟨value⟩ This is an actively-confirmed vulnerability, not just a version match.
- Plugin '⟨slug⟩' exists in CVE database but version not detected: ⟨db_note⟩. Slug '⟨slug⟩' has historical CVEs but no detectable version. Cannot determine patched status from the outside.
- WPScan API lookup failed: ⟨value⟩: ⟨e⟩
- WPScan: ⟨slug⟩ v⟨ver⟩ — ⟨value⟩: Source: WPScan API CVEs: ⟨value⟩ Fixed in: ⟨value⟩

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# List installed plugins and versions (run on the server):
wp plugin list --format=table
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.i
- **compliance_v2 / cmmc**: RA.L2-3.11.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## References

- https://wpscan.com/api/v3/plugins/

## Run only this check

```
wpsecscan only plugin_cves https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
