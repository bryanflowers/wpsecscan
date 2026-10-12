---
id: mcp_endpoint_exposure
title: "MCP (Model Context Protocol) endpoint exposure (A3)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 127
---

# MCP (Model Context Protocol) endpoint exposure (A3)

**check_id**: `mcp_endpoint_exposure`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-IAA

## What it does

A3 (v2.6.0) — MCP (Model Context Protocol) endpoint exposure.

WordPress AI plugins are rapidly adopting Anthropic's Model Context
Protocol so LLM agents can call tools hosted on the WP install. Two
discovery patterns are emerging:

  • /.well-known/mcp.json  — service-description manifest
  • /wp-json/wp/v2/mcp / /wp-json/mcp/v1/{tools,resources,prompts}
      — the JSON-RPC tool/resource/prompt endpoints

An UNAUTHENTICATED MCP endpoint is effectively shell access — an
attacker can list every tool the plugin registered and invoke them.
Tools commonly include `write_post`, `update_option`, `run_shortcode`,
`execute_query`, all of which are RCE/CSRF-equivalent.

This check probes both discovery patterns and flags any 200 response
without authentication as critical.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high | MCP endpoint exposed without authentication: ⟨route⟩ | MCP tools are effectively RCE primitives for an LLM agent. 1. Add 'permission_callback' =&gt; function() { return is_user_logged_in() && current_user_can('manage_options'); } to every register_rest_route() call the MCP plugin registers. 2. Until fixed, block these paths at the WAF: ⟨route⟩ 3. Audit which TOOLS the plugin registered — `write_post`, `update_option`, `run_shortcode`, `execute_query` are RCE-equivalent. |
| low | MCP endpoint registered (auth-gated): ⟨route⟩ | MCP is installed but properly auth-gated. Periodically audit which tools are exposed (use the plugin's admin panel) and remove any unused tool registrations. |

## Evidence the check records

- MCP endpoint exposed without authentication: ⟨route⟩: GET ⟨route⟩ → HTTP 200. ⟨tool_summary⟩ Body (truncated): ⟨value⟩
- MCP endpoint registered (auth-gated): ⟨route⟩: GET ⟨route⟩ → HTTP ⟨value⟩ (auth required, good).

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only mcp_endpoint_exposure https://example.com
```

`only` runs this check alone and prints its findings.
