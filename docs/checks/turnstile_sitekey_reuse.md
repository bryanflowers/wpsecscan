---
id: turnstile_sitekey_reuse
title: "Captcha sitekey placeholder / domain audit (A32)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Other"
words: 148
---

# Captcha sitekey placeholder / domain audit (A32)

**check_id**: `turnstile_sitekey_reuse`
**aggressive**: no
**category**: Other
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566 — Phishing
**CWE**: CWE-1188
**D3FEND**: D3-IAA

## What it does

A32 (v2.6.0) — Cloudflare Turnstile / hCaptcha sitekey reuse.

The Turnstile / hCaptcha / reCAPTCHA sitekey is intentionally public,
but reuse is suspicious — if the same sitekey appears on unrelated
domains, an attacker may be embedding it on a phishing site that
mirrors the operator's challenge UX. Cloudflare ranks sitekey-domain
mismatch as a fraud signal.

We extract the sitekey from the homepage and surface an advisory if
the sitekey is empty/placeholder OR if Cloudflare's domain restriction
hasn't been set ("*" allows any domain to use it).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Captcha sitekey looks like a placeholder: ⟨k⟩ | Replace the sitekey with the real value from your Cloudflare Turnstile / hCaptcha / reCAPTCHA dashboard. |
| info | Captcha sitekey detected: ⟨k⟩ — verify domain allow-list | In Cloudflare Turnstile / hCaptcha / reCAPTCHA dashboard, ensure this sitekey's 'Domains' setting is restricted to your apex + relevant subdomains, NOT '*' (any-origin). |

## Evidence the check records

- Captcha sitekey detected: ⟨k⟩ — verify domain allow-list: Sitekey: ⟨k⟩ Sitekey-domain reuse is a phishing signal — Cloudflare ranks captcha-puzzle submissions higher when the sitekey is used outside its registered allow-list.
- Captcha sitekey looks like a placeholder: ⟨k⟩: Inline HTML sitekey: ⟨k⟩ This appears to be a default/template value. The captcha will not protect any form on this site.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-23
- **compliance_map / iso_27001**: A.8.27

## Run only this check

```
wpsecscan only turnstile_sitekey_reuse https://example.com
```

`only` runs this check alone and prints its findings.
