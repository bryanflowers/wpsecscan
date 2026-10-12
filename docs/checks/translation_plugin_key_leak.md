---
id: translation_plugin_key_leak
title: "Translation plugin API key leak (A27)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 151
---

# Translation plugin API key leak (A27)

**check_id**: `translation_plugin_key_leak`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-798
**D3FEND**: D3-CRO

## What it does

A27 (v2.6.0) — Polylang / WPML / TranslatePress / WeGlot API-key leak.

Translation plugins use Google Translate / DeepL / Azure Translator to
machine-translate content. The API key is stored in wp_options and is
SUPPOSED to be server-side only — but several plugins exposed it via:

  • A REST endpoint that returned the option's value for any logged-in
    user (CVE family in 2024).
  • A JS settings page that leaked the key into the rendered form via
    value="..." (saved-and-redisplayed pattern).
  • Frontend translate-on-the-fly widgets where the key is loaded into
    a window-global.

Passive: scan the homepage + admin login page (which sometimes loads
plugin JS) for Google/DeepL/Azure-Translator API key patterns.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨provider⟩ API key leaked into public page | 1. REVOKE the ⟨provider⟩ key NOW at the provider's console. 2. Issue a new key, store it ONLY in wp-config.php or a .env file the WP plugin reads server-side. 3. Update the translation plugin to a version that doesn't render the key into HTML/JS. 4. Set provider-side billing alerts at 25%/50%/100% of quota. |

## Evidence the check records

- ⟨provider⟩ API key leaked into public page: GET ⟨path⟩ body contains a ⟨provider⟩ key (prefix: ⟨value⟩...) Pattern matched at offset ⟨value⟩. Translation API keys grant access to a paid quota; an attacker can drain it to inflate the operator's bill.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only translation_plugin_key_leak https://example.com
```

`only` runs this check alone and prints its findings.
