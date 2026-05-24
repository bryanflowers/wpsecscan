# Default credentials probe

**check_id**: `default_creds`
**aggressive**: yes
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078.001 — Default Accounts

## What it does

Default-credentials probe — strictly capped at 10 attempts against
well-known *shipped* defaults from plugin/theme install guides.

This is NOT brute force. It tests one specific question: "did anyone leave
the install-wizard's default credentials in place?" The list never grows
beyond 10; module-load asserts that bound. Each attempt is paced 3s apart;
if the site throttles, we abort.

Opt-in via aggressive mode only.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2.2
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17
- **compliance_v2 / hitrust**: 01.f
- **compliance_v2 / cmmc**: IA.L1-3.5.5
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan --target https://example.com --only default_creds
```
