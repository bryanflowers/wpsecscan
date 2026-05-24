"""NFT mint endpoint public-access probe.

Round-64 #72 — NFT-mint plugins (WP NFT Marketplace, ETH NFT WP, etc.)
sometimes expose unauthenticated mint endpoints under /wp-json/nft/*.
An unauth-callable mint is either (a) free-NFT-DoS on the contract gas
budget, or (b) actual unauthorised mint of tokens to attacker addresses.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

_PROBE_PATHS = (
    "/wp-json/nft/v1/mint",
    "/wp-json/nft/v1/airdrop",
    "/wp-json/nft-marketplace/v1/mint",
    "/wp-json/nft-marketplace/v1/list",
    "/wp-json/eth/v1/mint",
    "/wp-json/web3/v1/mint",
    "/wp-json/wp-nft/v1/mint",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        # POST a token-shaped body; expect 401/403 if properly locked
        r = await client.post(
            path,
            json={"to": "0x0000000000000000000000000000000000000000", "tokenId": 999999, "amount": 1},
            headers={"Content-Type": "application/json"},
        )
        if r is None or r.status_code == 404:
            continue
        if r.status_code in (200, 202):
            findings.append(
                Finding(
                    severity="critical",
                    title=f"NFT mint endpoint reachable unauthenticated: {path}",
                    evidence=f"POST {path} -> {r.status_code}\n  Body (first 200): {(r.text or '')[:200]!r}",
                    remediation=(
                        "An unauth mint endpoint can drain your contract's gas budget OR mint tokens to attacker wallets.\n"
                        "Require a signed message from the connected wallet on the API side.\n"
                        "Verify the signer is allow-listed in your contract before calling mint().\n"
                        "Add per-IP + per-wallet rate limits."
                    ),
                    url=client.url(path),
                )
            )
        elif r.status_code == 400:
            # Sometimes the endpoint accepts the request but rejects the body shape — still concerning
            body = (r.text or "")[:200]
            if "auth" not in body.lower() and "login" not in body.lower():
                findings.append(
                    Finding(
                        severity="medium",
                        title=f"NFT endpoint accepts unauthenticated requests (rejected on body shape): {path}",
                        evidence=f"POST {path} -> 400; body: {body!r}\n  No auth-related rejection message",
                        remediation="Verify the endpoint enforces wallet-signature auth, not just JSON-schema validation.",
                        url=client.url(path),
                    )
                )

    return findings
