---
id: ai_agent_tool_injection
title: "WP AI-agent tool-call injection probe (F18)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 87
---

# WP AI-agent tool-call injection probe (F18)

**check_id**: `ai_agent_tool_injection`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059 — Command & Scripting Interpreter
**CWE**: CWE-77
**D3FEND**: D3-NTA

## What it does

F18 (v2.8.1) — WP AI agent tool-call injection probe.

Plugins like AI Engine, Bertha, GetGenie expose a tool/function-
calling surface to LLMs. If the tool-dispatch endpoint accepts
input that influences which tool gets called without server-side
allow-listing, attackers can pivot from chat-prompt to admin-write.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F18: AI-agent plugin(s) detected: ⟨value⟩ — audit tool-call surface | Update plugin to current version. In settings, restrict tool-calling to admin-role only. If the plugin exposes a 'function-calling' or 'agent' mode, disable until you audit the allowed-tools list. |
| info | F18: no AI-agent plugins detected | No action needed. |

## Evidence the check records

- F18: AI-agent plugin(s) detected: ⟨value⟩ — audit tool-call surface: Detected: ⟨value⟩. These plugins expose LLM tool-calls which CAN write posts, change settings, or execute shortcodes if not server-side-allow-listed.
- F18: no AI-agent plugins detected: None of the 4 fingerprinted plugin paths responded.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SI.L2-3.14.3
- **compliance_v2 / nist_csf**: GV.OC-05
- **compliance_v2 / cis_v8**: 3.13
- **compliance_v2 / iso_27001_2022**: A.8.34

## Run only this check

```
wpsecscan only ai_agent_tool_injection https://example.com
```

`only` runs this check alone and prints its findings.
