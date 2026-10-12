---
id: ai_prompt_injection_passive
title: "AI/LLM-plugin prompt-injection surface (#51)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 79
---

# AI/LLM-plugin prompt-injection surface (#51)

**check_id**: `ai_prompt_injection_passive`
**aggressive**: no
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059 — Command and Scripting Interpreter
**CWE**: CWE-94
**D3FEND**: D3-IVA

## What it does

Passive AI/LLM-integration plugin fingerprint.

Round-64 #51 — many WP sites now expose LLM endpoints (AI Engine, GPT-
Chatbot, Bertha AI etc.). Indirect prompt-injection becomes a stored-
XSS-equivalent class of bug. This check fingerprints known LLM plugins
and probes a handful of unauthenticated prompt endpoints, flagging any
that respond without a nonce.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Unauthenticated LLM prompt endpoint reachable: ⟨slug⟩ | Restrict the prompt endpoint behind an auth check (cookie + nonce). Add rate limiting (per-IP + per-token-burn budget). Without these, the endpoint is both a free LLM proxy for attackers AND a stored-prompt-injection vector for your site's own pages. |
| info | AI/LLM-integration plugins detected: ⟨value⟩ | Indirect prompt-injection is now a real attack surface for LLM-integrated WP plugins. Review each plugin's settings for: anonymous-prompt allowed? rate limited? output sanitised? Treat LLM output rendered into pages as untrusted (CSP + escaping). |

## Evidence the check records

- AI/LLM-integration plugins detected: ⟨value⟩: ⟨count⟩ LLM plugin(s) fingerprinted via /wp-content/plugins/&lt;slug&gt;/readme.txt
- Unauthenticated LLM prompt endpoint reachable: ⟨slug⟩: POST ⟨endpoint⟩ -&gt; ⟨status⟩ (no nonce / no auth required)

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.3
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only ai_prompt_injection_passive https://example.com
```

`only` runs this check alone and prints its findings.
