# Compliance flows

WPSecScan has check-level mappings for **12 frameworks**:

- PCI-DSS 4.0 + NIST 800-53 Rev. 5 + ISO 27001
- HIPAA + SOC 2 + FedRAMP + GDPR Article references
- HITRUST CSF v11.4 + CMMC 2.0 + NIST CSF 2.0 + CIS Critical Controls v8 + ISO 27001:2022

Separately, OWASP Top 10 2021 and MITRE ATT&CK tags are on every check, and
CWE and D3FEND tags are on most (not all). These are tag taxonomies, not
compliance frameworks. Cyber Essentials Plus and Essential 8 exist only as
scorecard helpers in `wpsecscan/compliance_v28.py`, not as per-check
mappings.

## Pick a framework lens

```
WPSECSCAN_COMPLIANCE_FRAMEWORK=hitrust wpsecscan https://yoursite.com
```

Valid values: `hitrust`, `cmmc`, `nist_csf`, `cis_v8`, `iso_27001_2022`.
For a single-framework gap analysis of the latest scan, run
`wpsecscan compliance audit https://yoursite.com --framework hitrust`.

The framework-audit check adds findings that map the scan results to
that framework's controls.

## PCI 4.0 evidence pack

For sites accepting cards (Woo, Stripe, PayPal, Square), the payment
check writes an evidence pack during a normal scan:

```
wpsecscan https://yoursite.com
```

Writes `~/.wpsecscan/pci_evidence/<host>.json` (override the directory with
`WPSECSCAN_PCI_EVIDENCE_DIR`) containing the
controls covered, payment plugins detected, and a checklist of SAQ-A /
SAQ-A-EP requirements. Attach to your QSA workpaper.

## Where the mappings live

- `wpsecscan/data/check_tags.json` — OWASP / ATT&CK / CWE / D3FEND tags
- `wpsecscan/data/compliance_map.json` — PCI / NIST 800-53 / ISO 27001:2013
- `wpsecscan/data/compliance_extra.json` — HIPAA / SOC 2 / FedRAMP / GDPR
- `wpsecscan/data/compliance_v2.json` — HITRUST / CMMC / NIST CSF 2.0 / CIS v8 / ISO 27001:2022

You can override any of these by dropping a same-named file into
`~/.wpsecscan/` — it's merged at scan time (user file wins).
