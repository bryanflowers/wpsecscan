---
id: multisite
title: "WordPress Multisite audit"
severity_max: medium
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 78
---

# WordPress Multisite audit

**check_id**: `multisite`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium (some findings take their severity at run time)
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WordPress Multisite audit.

Multisite (Network) installations have extra attack surface: the network admin,
signup forms, sunrise.php drop-in, and per-site subdirectory/subdomain access.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (medium, low, info) | Multisite endpoint reachable: ⟨value⟩ | If this site doesn't need ⟨value⟩, block it at the server. For open signups specifically: Network Admin → Settings → Allow new registrations → Disabled. |
| info | Not a Multisite installation (no multisite endpoints detected) | No action needed. |
| info | WordPress Multisite (Network) installation detected | If multisite is intentional: lock down the network admin to admin IPs, disable open signups unless needed, and audit sunrise.php for legit content. If multisite is NOT intentional, you've found a real misconfig. |

## Evidence the check records

- WordPress Multisite (Network) installation detected: Probes for /wp-signup.php, /wp-activate.php, or /wp-admin/network/ returned multisite-shaped responses. Multisite installs have additional admin surface (the Network Admin) and per-site subdomain/subdir handling.
- Not a Multisite installation (no multisite endpoints detected): Probed ⟨count⟩ known multisite paths; none returned multisite-shaped responses.
- Multisite endpoint reachable: ⟨value⟩: GET ⟨value⟩ -&gt; HTTP ⟨value⟩ ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.18

## Run only this check

```
wpsecscan only multisite https://example.com
```

`only` runs this check alone and prints its findings.
