# Mixed-content (HTTP-in-HTTPS) audit

**check_id**: `mixed_content`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Mixed-content audit.

HTTPS pages that load HTTP resources (scripts, images, fonts) leak the page
contents to network attackers and break the integrity guarantee. Modern
browsers block most of these but legacy plugins/themes still emit them.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only mixed_content
```
