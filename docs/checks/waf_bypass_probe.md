# WAF bypass/passthrough probe

**check_id**: `waf_bypass_probe`
**aggressive**: yes
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WAF bypass / passthrough probe.

After the `waf` check has detected a WAF, this probes whether it actually
FILTERS or just fingerprints. We send a benign-looking but WAF-trigger string
in a query parameter and compare the response against a control.

If the WAF blocks: status 403/406/501 or response body wildly different.
If the WAF passes the trigger through: same response shape as control → flag.

Aggressive-only (sends a `<script>` token).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.16
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only waf_bypass_probe
```
