# Payment/PCI 4.0 deep audit (#58-62)

**check_id**: `payment_commerce_deep`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-311
**D3FEND**: D3-CR

## What it does

Round-59 #58-62 — Payment / commerce deep audit.

#58 Stripe/PayPal/Square config — detect each plugin + check that
   `pk_test_` keys aren't accidentally leaking in production HTML.
#59 PCI-DSS 4.0 checklist (informational guidance per finding)
#60 PCI evidence mode — emit a JSON evidence pack alongside findings
   so QSAs can include in their workpaper.
#61 3DS2 check — does the merchant's Stripe/PayPal integration enforce
   3DS2 on EU cards? Best-effort via the JS init params.
#62 Order/refund IDOR — `/wp-admin/admin-ajax.php?action=woocommerce_get_refunded_order_items&order_id=N`
   without auth.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.5.34
- **compliance_extra / hipaa**: 164.308(a)(8)
- **compliance_extra / soc2**: CC8.1
- **compliance_extra / fedramp**: SI-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan --target https://example.com --only payment_commerce_deep
```
