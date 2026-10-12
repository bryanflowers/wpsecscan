---
id: host_header_validation
title: "Host-header validation on admin endpoints (DNS-rebinding)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 200
---

# Host-header validation on admin endpoints (DNS-rebinding)

**check_id**: `host_header_validation`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-20
**D3FEND**: D3-IAA

## What it does

Item #7 — Host-header validation on admin endpoints.

A site that serves canonical WordPress content for any Host header is
vulnerable to DNS rebinding: an attacker hosts a domain whose A record
flips to the victim's IP, the visitor's browser sends a request with
the malicious Host, and the server happily serves /wp-admin under that
hostname. Combined with a stored XSS or a misconfigured CORS, this
becomes an admin-level browser-side intranet probe.

This is distinct from the existing `dns_rebinding` check, which probes
SSRF-via-rebind on outbound fetches. This one looks at INBOUND Host
validation on the admin surface.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Possible DNS-rebinding susceptibility (⟨count⟩ admin endpoint(s) accept spoofed Host) | Constrain the web server to the canonical hostname: • nginx: declare `server_name ⟨host⟩;` and add a catch-all server block: `server { listen 443 ssl default_server; return 421; }` • Apache: `UseCanonicalName On` + `UseCanonicalPhysicalPort On` + per-vhost ServerName Also define `WP_HOME` and `WP_SITEURL` in wp-config.php so WordPress core enforces the canonical URL even if the server config drifts. |
| info | Host-header validation — clean (⟨probed⟩ probes) | No action needed. |

## Evidence the check records

- Possible DNS-rebinding susceptibility (⟨count⟩ admin endpoint(s) accept spoofed Host): The server returned canonical WordPress content even when the Host header did not match the canonical hostname: ⟨value⟩ A DNS-rebinding attack uses a malicious domain whose A record briefly points at the victim's IP. The browser sends the request with the malicious Host header — if the server doesn't validate Host, the attacker can tunnel admin-shaped requests to the victim's intranet through the visitor's browser.
- Host-header validation — clean (⟨probed⟩ probes): Sent admin-endpoint requests with three spoofed Host headers; each was either rejected (400/403/421) or redirected back to the canonical hostname (⟨host⟩).

## Compliance mapping

- **compliance_map / pci_dss**: 6.5.7
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only host_header_validation https://example.com
```

`only` runs this check alone and prints its findings.
