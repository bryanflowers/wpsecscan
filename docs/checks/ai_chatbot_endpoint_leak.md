---
id: ai_chatbot_endpoint_leak
title: "AI-chatbot REST endpoint PII leak"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 88
---

# AI-chatbot REST endpoint PII leak

**check_id**: `ai_chatbot_endpoint_leak`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1213 — Data from Information Repositories

## What it does

Detect unauthenticated chat-log / conversation endpoints from popular
WordPress AI-chatbot plugins.

Plugins like Tidio, WP-Chatbot, AI Chat Elfsight, BotPenguin, AI Engine,
ChatBot for WordPress expose REST endpoints for chat history. When those
endpoints don't authenticate, visitor PII (names, emails, message
content) leaks. GDPR/CCPA reportable.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | AI-chatbot endpoint(s) leak conversation data unauthenticated (⟨count⟩) | 1. IMMEDIATELY: disable or restrict the offending plugin's REST namespace via the `rest_endpoints` filter, OR uninstall the plugin. 2. Assess GDPR/CCPA scope: chat content is personal data. Calculate the exposure window from access logs. 3. File a security report with the plugin author and check WPScan / Patchstack for a known CVE in the plugin's version. |

## Evidence the check records

- AI-chatbot endpoint(s) leak conversation data unauthenticated (⟨count⟩): Endpoints returning chat/conversation data without auth: ⟨lines⟩ JSON keys like `user_email`, `messages`, `conversation_id`, `visitor_name` indicate the endpoint is exposing real conversations. Every visitor who has ever talked to your site's chatbot is now enumerable by anyone.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only ai_chatbot_endpoint_leak https://example.com
```

`only` runs this check alone and prints its findings.
