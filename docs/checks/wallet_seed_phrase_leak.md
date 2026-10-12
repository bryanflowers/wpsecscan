---
id: wallet_seed_phrase_leak
title: "Wallet seed phrase leak (BIP-39 scan) (#75)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 84
---

# Wallet seed phrase leak (BIP-39 scan) (#75)

**check_id**: `wallet_seed_phrase_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-798
**D3FEND**: D3-FCR

## What it does

Wallet seed-phrase leak detection in exposed backups + .git.

Round-64 #75 — devs occasionally commit a wallet seed phrase to a .env
or test fixture, then expose the .git or a backup. We scan a small set
of probe paths and, if exposed, scan for BIP-39 wordlist matches — 12+
consecutive lowercase words from the BIP-39 dictionary is a near-zero-
false-positive signal of a seed phrase.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Possible wallet seed phrase in ⟨path⟩ | IMMEDIATELY: assume the wallet is compromised. Transfer all funds out to a NEW wallet whose seed has never been digital. Block the exposed path publicly. Audit how the file got into the docroot — usually a forgotten test fixture or backup file. |

## Evidence the check records

- Possible wallet seed phrase in ⟨path⟩: 12-word window at offset ⟨i⟩: ⟨phrase_start⟩ ... (⟨hits⟩/12 BIP-39 dictionary hits)

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only wallet_seed_phrase_leak https://example.com
```

`only` runs this check alone and prints its findings.
