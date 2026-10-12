---
id: nft_mint_pubapi
title: "NFT mint endpoint public-access probe (#72)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 82
---

# NFT mint endpoint public-access probe (#72)

**check_id**: `nft_mint_pubapi`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-285
**D3FEND**: D3-MFA

## What it does

NFT mint endpoint public-access probe.

Round-64 #72 — NFT-mint plugins (WP NFT Marketplace, ETH NFT WP, etc.)
sometimes expose unauthenticated mint endpoints under /wp-json/nft/*.
An unauth-callable mint is either (a) free-NFT-DoS on the contract gas
budget, or (b) actual unauthorised mint of tokens to attacker addresses.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | NFT mint endpoint reachable unauthenticated: ⟨path⟩ | An unauth mint endpoint can drain your contract's gas budget OR mint tokens to attacker wallets. Require a signed message from the connected wallet on the API side. Verify the signer is allow-listed in your contract before calling mint(). Add per-IP + per-wallet rate limits. |
| medium | NFT endpoint accepts unauthenticated requests (rejected on body shape): ⟨path⟩ | Verify the endpoint enforces wallet-signature auth, not just JSON-schema validation. |

## Evidence the check records

- NFT mint endpoint reachable unauthenticated: ⟨path⟩: POST ⟨path⟩ -&gt; ⟨value⟩ Body (first 200): ⟨value⟩
- NFT endpoint accepts unauthenticated requests (rejected on body shape): ⟨path⟩: POST ⟨path⟩ -&gt; 400; body: ⟨body⟩ No auth-related rejection message

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only nft_mint_pubapi https://example.com
```

`only` runs this check alone and prints its findings.
