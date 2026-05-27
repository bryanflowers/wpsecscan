"""A3 (v2.6.0) — MCP (Model Context Protocol) endpoint exposure.

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
"""
from __future__ import annotations

import json

from ..http import Client
from ..models import Finding


_MCP_ROUTES = (
    "/.well-known/mcp.json",
    "/wp-json/wp/v2/mcp",
    "/wp-json/mcp/v1/tools",
    "/wp-json/mcp/v1/resources",
    "/wp-json/mcp/v1/prompts",
    "/wp-json/ai-engine/v1/mcp/tools",
    "/wp-json/mwai/v1/mcp/tools",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for route in _MCP_ROUTES:
        step(f"MCP probe: {route}")
        r = await client.get(route)
        if r is None or r.status_code not in (200, 401, 403):
            continue

        if r.status_code == 200:
            tools_listed: list[str] = []
            try:
                data = json.loads(r.text or "{}")
                # Try common shapes: {"tools": [{"name": "x"}, ...]}
                # or JSON-RPC reply: {"result": {"tools": [...]}}
                node = data.get("tools") or (data.get("result") or {}).get("tools") or []
                if isinstance(node, list):
                    for t in node:
                        if isinstance(t, dict) and "name" in t:
                            tools_listed.append(str(t["name"]))
            except (ValueError, AttributeError):
                pass

            sev = "critical" if tools_listed else "high"
            tool_summary = (
                f"Tools exposed: {', '.join(tools_listed[:15])}"
                + (f" (+{len(tools_listed) - 15} more)" if len(tools_listed) > 15 else "")
                if tools_listed
                else "MCP discovery returned 200 but tool list wasn't parseable."
            )
            findings.append(Finding(
                severity=sev,
                title=f"MCP endpoint exposed without authentication: {route}",
                evidence=(
                    f"GET {route} → HTTP 200.\n"
                    f"{tool_summary}\n"
                    f"Body (truncated): {(r.text or '')[:300]}"
                ),
                remediation=(
                    "MCP tools are effectively RCE primitives for an LLM agent.\n"
                    "1. Add 'permission_callback' => function() { return is_user_logged_in() "
                    "&& current_user_can('manage_options'); } to every register_rest_route() "
                    "call the MCP plugin registers.\n"
                    "2. Until fixed, block these paths at the WAF: " + route + "\n"
                    "3. Audit which TOOLS the plugin registered — `write_post`, "
                    "`update_option`, `run_shortcode`, `execute_query` are RCE-equivalent."
                ),
                url=client.url(route),
                extra={"route": route, "tools": tools_listed,
                        "category": "mcp-exposure"},
            ))
        else:
            # 401/403 — still useful signal that MCP is installed
            findings.append(Finding(
                severity="low",
                title=f"MCP endpoint registered (auth-gated): {route}",
                evidence=f"GET {route} → HTTP {r.status_code} (auth required, good).",
                remediation=(
                    "MCP is installed but properly auth-gated. Periodically audit "
                    "which tools are exposed (use the plugin's admin panel) and "
                    "remove any unused tool registrations."
                ),
                url=client.url(route),
                extra={"route": route, "status": r.status_code},
            ))
    return findings
