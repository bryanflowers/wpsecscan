---
id: ai_agent_webhook_leak
title: "AI chatbot relay-endpoint / key leak (A2)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 124
---

# AI chatbot relay-endpoint / key leak (A2)

**check_id**: `ai_agent_webhook_leak`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-IAA

## What it does

A2 (v2.6.0) — AI chatbot webhook leak.

Modern WP chatbot plugins (AI Engine, WPBot, BotPenguin, Tidio, Crisp)
POST conversation transcripts to an LLM provider via a stored webhook
URL. When that URL or the plugin's relay endpoint is unauthenticated,
anyone can:

  • Exfil past conversations (privacy + competitive intelligence leak).
  • Replay conversations to inflate the operator's OpenAI bill.
  • Inject crafted prompts into the next conversation.

Passive: probe the common relay endpoints + scan the homepage HTML for
inline-script `apiUrl` / `webhookUrl` properties that leak the key.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | AI chatbot relay endpoint accepts unauthenticated POST: ⟨route⟩ | Require authentication on the relay endpoint. In the plugin's register_rest_route() call, set 'permission_callback' to a function that verifies the request's nonce + capability. Until then, block POST ⟨route⟩ at the WAF. |
| medium | AI chatbot config leaks upstream URL or key into frontend JS | Move the upstream URL / API key out of the page-rendered JS into a server-side AJAX relay. Frontend code should call your own /wp-json/.../chat endpoint, which forwards to the LLM provider with a server-held key. |

## Evidence the check records

- AI chatbot relay endpoint accepts unauthenticated POST: ⟨route⟩: POST ⟨route⟩ → HTTP ⟨value⟩. Body (truncated): ⟨value⟩
- AI chatbot config leaks upstream URL or key into frontend JS: Inline JS contains: ⟨value⟩ Leaked value: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only ai_agent_webhook_leak https://example.com
```

`only` runs this check alone and prints its findings.
