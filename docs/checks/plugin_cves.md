# Plugin CVE matching

**check_id**: `plugin_cves`
**aggressive**: no
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Plugin CVE matching against the Wordfence Intelligence DB.

Uses plugin versions discovered by the `plugins` check (ctx['shared']['plugins']).
When aggressive mode is on, also runs confirmed-exploit signatures from
data/exploit_signatures.json against matching plugins.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.i
- **compliance_v2 / cmmc**: RA.L2-3.11.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only plugin_cves
```
