---
id: web3_wallet_connector_audit
title: "Web3 wallet-connector plugin audit (#71)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 73
---

# Web3 wallet-connector plugin audit (#71)

**check_id**: `web3_wallet_connector_audit`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-345
**D3FEND**: D3-MFA

## What it does

Web3 wallet-connector plugin audit.

Round-64 #71 — WP plugins like MetaMask Login, WalletConnect, and
Web3 Login integrate browser wallets. Common misconfigurations: the
RPC provider URL is hard-coded to a third party (privacy leak), the
chain ID is wrong (replay-attack surface), the signature-verification
message doesn't include a nonce (replay across sites).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Web3 RPC provider URL hard-coded to public service: ⟨rpc⟩ | Hard-coded public RPC ⟨rpc⟩ means every wallet interaction is logged by that provider. Either: (a) Run your own node (geth/erigon) and point the plugin at it. (b) Use a provider plan that supports IP-restricted keys. |
| info | Web3 wallet-connector plugin(s) detected: ⟨value⟩ | Audit each Web3 connector for: - chainId pinned to the network you actually want (replay-attack guard) - signMessage payload includes site nonce + timestamp (replay-attack guard) - RPC provider URL is your own (privacy) - on-chain transaction calls always validated server-side (don't trust the wallet's word) |

## Evidence the check records

- Web3 wallet-connector plugin(s) detected: ⟨value⟩: Plugins: ⟨detected⟩
- Web3 RPC provider URL hard-coded to public service: ⟨rpc⟩: Found ⟨rpc⟩ embedded in ⟨path⟩

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: IA-3
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only web3_wallet_connector_audit https://example.com
```

`only` runs this check alone and prints its findings.
