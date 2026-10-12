---
id: login_timing
title: "Login timing side-channel (user enum)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 161
---

# Login timing side-channel (user enum)

**check_id**: `login_timing`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.002 — Gather Victim Identity Information: Email Addresses

## What it does

Login timing side-channel — username enumeration via response timing.

WordPress's wp-login.php often returns DIFFERENT response times depending on
whether the username exists:
  - User exists, password wrong  → bcrypt hash comparison runs (~300+ ms)
  - User doesn't exist           → fast bail (~50-100 ms)

That delta lets an attacker prune their brute-force list to only valid users.

Probe: send 5 wrong-password attempts for `admin` (likely valid) and 5 for a
random synthetic username (definitely invalid). Compare medians. Flag ≥40%
delta as a username-enumeration vector.

Passive (no real password guesses, just timing).

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Login timing leak: valid user takes ⟨delta_pct⟩% longer than invalid | WP core mitigates this somewhat in recent versions; if you're on an older release, upgrade. For belt-and-braces, install a plugin like 'Hide My WP Ghost' that adds a constant-time pre-check, OR enable a WAF rule that adds 100-300 ms of jitter to all wp-login.php POSTs (Cloudflare: Workers; Nginx: ngx_http_delay_module). |
| info | Login timing probe inconclusive — too many network errors | No action. |
| info | Login timing probe skipped: /wp-login.php not reachable | No action. |
| info | No exploitable login timing leak (⟨delta_pct⟩% delta within tolerance) | No action — timing-based username enumeration not viable here. |

## Evidence the check records

- Login timing probe skipped: /wp-login.php not reachable: GET /wp-login.php -&gt; ⟨value⟩
- Login timing probe inconclusive — too many network errors: Got ⟨count⟩ valid-user samples, ⟨count⟩ invalid-user samples.
- Login timing leak: valid user takes ⟨delta_pct⟩% longer than invalid: ⟨sample_table⟩ WordPress runs bcrypt comparison only for known usernames. The timing delta lets an attacker enumerate which usernames exist on your site by measuring response time, even with no error-message difference.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.5.15
- **compliance_v2 / hitrust**: 01.r
- **compliance_v2 / cmmc**: IA.L1-3.5.1
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan only login_timing https://example.com
```

`only` runs this check alone and prints its findings.
