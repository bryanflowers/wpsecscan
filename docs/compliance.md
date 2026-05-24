# Compliance flows

WPSecScan tags every finding with mappings across **9 frameworks**:

- OWASP Top 10 2021 + MITRE ATT&CK + CWE + D3FEND (every check)
- PCI-DSS 4.0 + NIST 800-53 Rev. 5 + ISO 27001:2022
- HIPAA + FERPA + SOC 2 + FedRAMP + GDPR Article references
- HITRUST CSF v11.4 + CMMC 2.0 + NIST CSF 2.0 + CIS Critical Controls v8

## Pick a framework lens

```
wpsecscan --target https://yoursite.com --compliance-framework hitrust
```

Valid values: `hitrust`, `cmmc`, `nist_csf`, `cis_v8`, `iso_27001_2022`.

The JSON report gets a `compliance_<framework>` section keyed by control
ID, listing every finding that maps to that control. The HTML report
adds a top-of-page compliance summary table.

## PCI 4.0 evidence pack

For sites accepting cards (Woo, Stripe, PayPal, Square):

```
wpsecscan --target https://yoursite.com --pci-evidence
```

Writes `~/.wpsecscan/pci_evidence/<host>.json` containing the
controls covered, payment plugins detected, and a checklist of SAQ-A /
SAQ-A-EP requirements. Attach to your QSA workpaper.

## Where the mappings live

- `wpsecscan/data/check_tags.json` — OWASP / ATT&CK / CWE / D3FEND
- `wpsecscan/data/compliance_map.json` — PCI / NIST 800-53 / ISO 27001:2013
- `wpsecscan/data/compliance_extra.json` — HIPAA / FERPA / SOC 2 / FedRAMP / GDPR
- `wpsecscan/data/compliance_v2.json` — HITRUST / CMMC / NIST CSF 2.0 / CIS v8 / ISO 27001:2022

You can override any of these by dropping a same-named file into
`~/.wpsecscan/` — it's merged at scan time (user file wins).
