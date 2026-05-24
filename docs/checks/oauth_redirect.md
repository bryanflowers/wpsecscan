# OAuth / login redirect-URI

**check_id**: `oauth_redirect`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1204.001 — User Execution: Malicious Link

## What it does

OAuth / login redirect-URI validation probe.

WordPress's wp-login.php and several OAuth plugins accept a `redirect_to` /
`redirect_uri` parameter and bounce the user to that URL after login. Sites
that don't restrict the destination to same-origin URLs let attackers craft
phishing links where the URL bar shows YOUR domain.

Probe: send a redirect URL that points to evil.example.com and check whether
the resulting Location header (or HTML meta refresh) points to the attacker.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only oauth_redirect
```
