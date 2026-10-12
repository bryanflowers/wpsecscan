---
id: webhook_url_fingerprint
title: "Webhook URL fingerprint (Discord/Slack/Telegram) (#65)"
severity_max: high
severity_dynamic: true
aggressive: false
category: "GraphQL & APIs"
words: 78
---

# Webhook URL fingerprint (Discord/Slack/Telegram) (#65)

**check_id**: `webhook_url_fingerprint`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high (some findings take their severity at run time)
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1567.002 — Exfiltration to Cloud Storage
**CWE**: CWE-798
**D3FEND**: D3-SCM

## What it does

Webhook URL fingerprint — flag Discord/Slack/Telegram outbound URLs.

Round-64 #65 — many WP plugins let admins paste a Discord/Slack/
Telegram webhook URL for notifications. These URLs are themselves
credentials (anyone with the URL can post to that channel). The
companion plugin exposes /wp-json/wpsecscan-companion/v1/webhooks
returning [{option_key, url}]. We flag any that match known webhook
hostnames so admins can audit + rotate them.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (high, medium, low) | ⟨service⟩ webhook configured in option ⟨option⟩ | Document this ⟨service⟩ integration in your secret-registry. Rotate the webhook URL if you suspect leak (anyone who has read the WP DB or wp_options table has the URL). Consider moving the URL into a wp-config.php constant or env-var instead of wp_options. |

## Evidence the check records

- ⟨service⟩ webhook configured in option ⟨option⟩: Option ⟨option⟩ contains a ⟨service⟩ webhook URL. Masked: ⟨masked⟩ ⟨why⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only webhook_url_fingerprint https://example.com
```

`only` runs this check alone and prints its findings.
