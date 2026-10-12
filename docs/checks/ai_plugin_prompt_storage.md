---
id: ai_plugin_prompt_storage
title: "AI plugin prompt-injection surface (A1)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 192
---

# AI plugin prompt-injection surface (A1)

**check_id**: `ai_plugin_prompt_storage`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059 — Command & Scripting Interpreter
**CWE**: CWE-94
**D3FEND**: D3-IAA

## What it does

A1 (v2.6.0) — AI plugin prompt-injection storage detection.

Several popular WP AI plugins (AI Engine, AIomatic, OpenAI Powered Plugin,
ChatGPT Powered, GPT3 AI Content Generator) read user-controlled fields
— comments, product descriptions, ACF fields, post excerpts — and feed
them into an LLM prompt without sanitising for the prompt-injection
attack surface.

This check is passive: it fingerprints the AI plugin via the rendered
HTML and well-known endpoints, then surfaces a high-severity finding
recommending the operator audit ALL user-content fields the plugin
ingests. The actual exploit is out of scope (requires manual review of
how each plugin templates the user content into the prompt).

Indirect prompt injection has displaced CSRF as the #1 plugin bug class
in 2026 — every AI-enabled WP install needs a manual audit.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | AI plugin detected (⟨plugin_list⟩) — audit prompt-injection surface | 1. Manually audit every field this plugin reads into the LLM prompt. 2. Confirm the plugin separates the system prompt from user content via the OpenAI / Anthropic role-based API (not string concatenation). 3. Disable the plugin on any field that accepts unauthenticated input (comments, REST POSTs). 4. Move to an LLM provider that supports output-filtering / constitutional-AI safeguards if available. |

## Evidence the check records

- AI plugin detected (⟨plugin_list⟩) — audit prompt-injection surface: Detected: ⟨plugin_list⟩. AI plugins on WordPress commonly templates user-controlled content (comments, post excerpts, ACF fields, product descriptions) directly into the LLM prompt without separating the system-prompt from the user-supplied context. An attacker who can write a comment or product review can therefore manipulate the LLM's output — exfiltrate data, issue tool calls, or override the system prompt.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only ai_plugin_prompt_storage https://example.com
```

`only` runs this check alone and prints its findings.
