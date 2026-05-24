# Webhook endpoint discovery

**check_id**: `webhooks`
**aggressive**: no
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Webhook endpoint discovery.

Many WP plugins register webhook receivers under `/wp-json/<plugin>/v1/webhook`
or `/?wc-api=<plugin>` and many forget to validate signatures or restrict
sources. This check discovers them and probes for the auth requirement.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only webhooks
```
