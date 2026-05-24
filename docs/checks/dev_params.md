# Beta/test/debug query parameters

**check_id**: `dev_params`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-489
**D3FEND**: D3-SU

## What it does

Beta / test / debug parameter discovery.

Probes common 'unlock-the-hidden-feature' query parameters against the homepage.
A response that DIFFERS from the baseline indicates the parameter is consumed
somewhere in the code path — often by a forgotten debug toggle.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2.4
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only dev_params
```
