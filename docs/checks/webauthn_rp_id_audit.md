---
id: webauthn_rp_id_audit
title: "WebAuthn / Passkeys RP-ID audit (F22)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 100
---

# WebAuthn / Passkeys RP-ID audit (F22)

**check_id**: `webauthn_rp_id_audit`
**aggressive**: no
**category**: Authentication & session
**max severity**: low
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1556 — Modify Authentication Process
**CWE**: CWE-287
**D3FEND**: D3-IAA

## What it does

F22 (v2.8.1) — WebAuthn / Passkeys RP-ID audit.

Plugins like Passkeys, WP-WebAuthn, and Two-Factor's webauthn
provider must use the eTLD+1 hostname as the RP-ID. Misconfigured
RP-ID lets passkeys made on `app.example.com` work on
`evil.example.com` (or vice versa). We fingerprint the plugin
and emit an advisory; full RP-ID audit requires inspecting the
JS attestation flow, which we can't do passively.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | F22: WebAuthn / Passkeys plugin detected (⟨value⟩) — RP-ID audit recommended | In Settings → Passkeys/WebAuthn, verify the configured RP-ID is your eTLD+1 (e.g. `example.com`, not `www.example.com` or `*.example.com`). Audit the JS registration call for `rp.id === 'your-etld-plus-1'`. |
| info | F22: no WebAuthn / Passkeys plugin detected | No action needed. |

## Evidence the check records

- F22: WebAuthn / Passkeys plugin detected (⟨value⟩) — RP-ID audit recommended: Detected: ⟨value⟩. Cannot validate the configured Relying-Party ID without an authenticated registration flow.
- F22: no WebAuthn / Passkeys plugin detected: None of the 4 fingerprinted plugin paths responded.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.8.5
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## Run only this check

```
wpsecscan only webauthn_rp_id_audit https://example.com
```

`only` runs this check alone and prints its findings.
