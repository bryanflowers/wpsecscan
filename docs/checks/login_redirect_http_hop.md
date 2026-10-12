---
id: login_redirect_http_hop
title: "HTTP hop in /wp-login.php redirect chain"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 117
---

# HTTP hop in /wp-login.php redirect chain

**check_id**: `login_redirect_http_hop`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Detect an HTTP-hop in the redirect chain to /wp-login.php.

Even a single http:// hop in the redirect chain means login credentials
can travel in plaintext for one network hop — sufficient for a
man-in-the-middle on the same network to capture credentials. This is
distinct from a missing-HTTPS finding because the FINAL URL is HTTPS;
only the intermediate hop is broken.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Login redirect chain (⟨count⟩ hops) includes an http:// hop | 1. Make sure /wp-login.php (and /wp-admin) redirect DIRECTLY to their HTTPS counterparts — never via an http:// hop. 2. In wp-config.php: `define('FORCE_SSL_ADMIN', true);` (already default-on in recent WP versions, but verify). 3. Audit the web-server config for an `http → https` redirect that loses the /wp-login.php path along the way. Common bug: 301 to https://www.example.com/ (without preserving the path). |

## Evidence the check records

- Login redirect chain (⟨count⟩ hops) includes an http:// hop: Redirect chain from /wp-login.php: ⟨value⟩ Even though the FINAL destination is HTTPS, credentials POSTed into the login flow travel through an http:// intermediate, which a MITM on the local network can capture in plaintext. Browsers do show the green padlock on the final page, masking this issue.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 09.s
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only login_redirect_http_hop https://example.com
```

`only` runs this check alone and prints its findings.
