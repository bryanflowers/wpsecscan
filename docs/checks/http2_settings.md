---
id: http2_settings
title: "HTTP/2 fingerprint + EOL backend"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 103
---

# HTTP/2 fingerprint + EOL backend

**check_id**: `http2_settings`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software

## What it does

HTTP/2 fingerprint check.

Looks at httpx-reported h2 negotiation + Server header to infer the backend
HTTP/2 stack. Modern nginx (&gt;=1.13.10), Apache (mod_http2 &gt;=2.4.26), litespeed,
and cloudflare each have distinctive `Server:` advertisements. Flags any
backend that's known to be EOL or has unpatched H/2 CVEs.

(httpx already negotiates h2 via the `http2=True` we pass to Client.)

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | EOL HTTP backend detected: ⟨banner⟩ | Upgrade the web-server package to a current major. EOL HTTP/2 stacks accumulate stream-reset DoS, rapid-reset (CVE-2023-44487), HPACK-bomb, and h2c-smuggling CVEs that vendors no longer patch. |
| info | HTTP/2 fingerprint check — no response from / | No action. |
| info | HTTP/2 fingerprint: ⟨http_version⟩ via ⟨value⟩ | Hide the Server header in production — exact version disclosure makes CVE matching trivial. nginx: `server_tokens off;` Apache: `ServerTokens Prod` + `ServerSignature Off`. |

## Evidence the check records

- HTTP/2 fingerprint check — no response from /: Couldn't fetch / to inspect HTTP version.
- HTTP/2 fingerprint: ⟨http_version⟩ via ⟨value⟩: Server header: ⟨value⟩ Negotiated HTTP version: ⟨http_version⟩ No EOL backend versions matched the banner.
- EOL HTTP backend detected: ⟨banner⟩: Server header: ⟨server⟩ Negotiated: ⟨http_version⟩ ⟨note⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only http2_settings https://example.com
```

`only` runs this check alone and prints its findings.
