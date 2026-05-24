# External JS supply-chain audit

**check_id**: `js_supply_chain`
**aggressive**: no
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain

## What it does

JS + CSS supply-chain inventory.

Inventories every external host serving JS and stylesheets to your pages,
and flags unpinned references (no SRI hash). Both `<script src>` and
`<link rel=stylesheet>` are an SRI risk — a CDN compromise can poison your
JS via either vector.

Risky hosts (raw GitHub, unfamiliar CDNs) get higher severity than well-known
ones (jsdelivr, unpkg with SRI).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SA-9
- **compliance_map / iso_27001**: A.5.19
- **compliance_v2 / hitrust**: 06.j
- **compliance_v2 / cmmc**: SR.L2-3.17.1
- **compliance_v2 / nist_csf**: ID.SC-04
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.5.21

## Run only this check

```
wpsecscan --target https://example.com --only js_supply_chain
```
