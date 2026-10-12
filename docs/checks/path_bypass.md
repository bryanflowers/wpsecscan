---
id: path_bypass
title: "Path-normalisation bypass probe"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 181
---

# Path-normalisation bypass probe

**check_id**: `path_bypass`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-22
**D3FEND**: D3-RAC

## What it does

Path-normalisation bypass probe (aggressive).

Tests whether a WAF / front-end ACL can be bypassed via encoded path traversal:
  - `..%2f` (URL-encoded /)
  - `..;/` (Tomcat path-parameter trick)
  - `%5c` (backslash, treated as / by some servers)
  - `..%252f` (double-URL-encoded /)
  - `..%c0%af` (overlong UTF-8 /)

Baseline /wp-admin/ + try each bypass variant. If a bypass returns a DIFFERENT
(non-403) response than the baseline, the ACL is bypassable.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | /wp-admin/admin.php is publicly reachable without auth | Restrict /wp-admin/ to admin IPs at the web server / WAF. |
| high | Path-normalisation bypass candidate: ⟨value⟩ | Configure your front-end to normalise paths BEFORE applying the ACL: - Nginx: `merge_slashes on; absolute_redirect off;` - Apache: enable `mod_rewrite` with `[B,QSA,NE]` flags on protection rules - Cloudflare: use Transform Rules to canonicalise URI before matching Or apply the ACL at the BACKEND (WordPress hooks) rather than the front-end. |
| info | No path-normalisation bypasses found | No action — your front-end ACL normalises paths consistently. |
| info | Path-bypass probe skipped — no baseline response | No action. |
| info | Path-normalisation bypass probe skipped (requires --aggressive) | No action. |

## Evidence the check records

- Path-normalisation bypass probe skipped (requires --aggressive): This sends ../, ..%2f, ..;/, %5c-style payloads against /wp-admin/.
- Path-bypass probe skipped — no baseline response: GET /wp-admin/admin.php returned None.
- /wp-admin/admin.php is publicly reachable without auth: GET /wp-admin/admin.php -&gt; HTTP 200 with ⟨base_len⟩ bytes (no login redirect).
- No path-normalisation bypasses found: Baseline /wp-admin/admin.php = HTTP ⟨base_status⟩; all ⟨value⟩ encoded variants matched the baseline.
- Path-normalisation bypass candidate: ⟨value⟩: Baseline GET /wp-admin/admin.php -&gt; HTTP ⟨base_status⟩ (⟨base_len⟩ bytes) Bypass GET ⟨path⟩ -&gt; HTTP ⟨status⟩ (⟨body_len⟩ bytes) The front-end (Nginx/Apache/Cloudflare) normalises the path differently than the backend (PHP-FPM/WordPress). Attacker can hit /wp-admin/ resources by bouncing through a path that the ACL doesn't match but the backend serves.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-community/attacks/Path_Traversal
- deep dive: https://portswigger.net/web-security/access-control/url-based

## Run only this check

```
wpsecscan only path_bypass https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
