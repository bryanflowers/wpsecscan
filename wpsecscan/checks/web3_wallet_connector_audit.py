"""Web3 wallet-connector plugin audit.

Round-64 #71 — WP plugins like MetaMask Login, WalletConnect, and
Web3 Login integrate browser wallets. Common misconfigurations: the
RPC provider URL is hard-coded to a third party (privacy leak), the
chain ID is wrong (replay-attack surface), the signature-verification
message doesn't include a nonce (replay across sites).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

_WALLET_PLUGINS = (
    "metamask-login",
    "walletconnect-login",
    "web3-login",
    "nft-login",
    "wp-web3-login",
    "cryptopay",
    "web3-store",
    "wp-web3",
)

# Public Ethereum RPC providers — using these from a logged-in admin page
# leaks every wallet interaction to the provider.
_PUBLIC_RPCS = (
    "mainnet.infura.io",
    "polygon-mainnet.g.alchemy.com",
    "eth-mainnet.g.alchemy.com",
    "rpc.ankr.com",
    "cloudflare-eth.com",
    "publicnode.com",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    detected = []
    for slug in _WALLET_PLUGINS:
        step(f"checking {slug}...")
        r = await client.get(f"/wp-content/plugins/{slug}/readme.txt")
        if r is not None and r.status_code == 200 and len(r.text or "") > 30:
            detected.append(slug)

    if not detected:
        return findings

    findings.append(
        Finding(
            severity="info",
            title=f"Web3 wallet-connector plugin(s) detected: {', '.join(detected)}",
            evidence=f"Plugins: {detected}",
            remediation=(
                "Audit each Web3 connector for:\n"
                "  - chainId pinned to the network you actually want (replay-attack guard)\n"
                "  - signMessage payload includes site nonce + timestamp (replay-attack guard)\n"
                "  - RPC provider URL is your own (privacy)\n"
                "  - on-chain transaction calls always validated server-side (don't trust the wallet's word)"
            ),
            url=client.url("/wp-content/plugins/"),
            extra={"plugins": detected},
        )
    )

    # Scan homepage + login page for public-RPC URLs (privacy leak)
    for path in ("/", "/wp-login.php", "/account/"):
        r2 = await client.get(path)
        if r2 is None or r2.status_code != 200:
            continue
        body = r2.text or ""
        for rpc in _PUBLIC_RPCS:
            if rpc in body:
                findings.append(
                    Finding(
                        severity="medium",
                        title=f"Web3 RPC provider URL hard-coded to public service: {rpc}",
                        evidence=f"Found {rpc!r} embedded in {path}",
                        remediation=(
                            f"Hard-coded public RPC {rpc} means every wallet interaction is logged by that provider.\n"
                            "Either:\n"
                            "  (a) Run your own node (geth/erigon) and point the plugin at it.\n"
                            "  (b) Use a provider plan that supports IP-restricted keys."
                        ),
                        url=client.url(path),
                        extra={"rpc": rpc},
                    )
                )
                break

    return findings
