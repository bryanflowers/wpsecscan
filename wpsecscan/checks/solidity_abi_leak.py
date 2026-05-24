"""Solidity contract ABI leak detection.

Round-64 #74 — Web3 plugins that interact with a custom Solidity
contract usually need the contract's ABI (Application Binary Interface)
on the client side to call methods. The ABI itself isn't secret, but its
location often reveals: (a) the contract address (good for tracking
attacks), (b) admin-only methods (an attacker now knows what privileged
calls exist), (c) sometimes the SOURCE code in a comment block.
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding

_PROBE_PATHS = (
    "/wp-content/uploads/abi/",
    "/wp-content/uploads/contracts/",
    "/wp-content/uploads/web3/abi.json",
    "/wp-content/abi.json",
    "/wp-content/themes/web3/abi.json",
    "/abi/",
    "/contracts/abi.json",
    "/build/contracts/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        # Two cases: directory listing or actual ABI JSON
        is_listing = "<title>Index of" in body or "Parent Directory" in body
        is_abi = False
        admin_methods: list[str] = []
        try:
            data = json.loads(body)
            # Truffle/Hardhat output: {"abi": [...]}, or just [...]
            abi = data.get("abi", data) if isinstance(data, dict) else data
            if isinstance(abi, list) and abi and isinstance(abi[0], dict) and "type" in abi[0]:
                is_abi = True
                # Find functions that look admin-restricted
                for fn in abi:
                    if fn.get("type") == "function":
                        name = fn.get("name", "")
                        if any(p in name.lower() for p in ("setowner", "withdraw", "pause", "mint", "burn", "setadmin", "destroy", "selfdestruct")):
                            admin_methods.append(name)
        except (ValueError, TypeError, KeyError):
            pass

        # Look for embedded source code (common in Hardhat artifacts)
        has_source = "pragma solidity" in body.lower() or "// SPDX-License-Identifier" in body

        if is_abi or is_listing or has_source:
            sev = "medium" if (admin_methods or has_source) else "low"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"Solidity contract ABI exposed at {path}",
                    evidence=(
                        f"GET {path} -> 200 ({len(body)} bytes)\n  "
                        + (f"Admin-like methods: {admin_methods[:6]}\n  " if admin_methods else "")
                        + (f"Source code embedded: yes\n  " if has_source else "")
                        + (f"Directory listing: yes\n  " if is_listing else "")
                    ),
                    remediation=(
                        "Move the ABI out of /wp-content/uploads (which is world-readable) into a non-public dir, "
                        "or ship it bundled in the plugin JS (so the URL fingerprint doesn't reveal the contract location).\n"
                        "If source code is embedded, strip artifacts down to ABI-only before publishing."
                    ),
                    url=client.url(path),
                    extra={"admin_methods": admin_methods},
                )
            )

    return findings
