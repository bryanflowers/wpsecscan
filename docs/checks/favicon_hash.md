# Favicon fingerprint hash (Shodan)

**check_id**: `favicon_hash`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

Favicon hash for operational intel (Shodan-compatible).

Computes the MMH3 32-bit hash of the base64-encoded favicon bytes — the same
hash Shodan uses for its `http.favicon.hash:N` query. Lets the user search
Shodan or Censys for OTHER sites with the same favicon (often: same admin's
sites, or sites in a compromised cluster).

We don't pull Shodan ourselves (would need an API key); we just compute the
hash and tell the user the search URL to paste.

mmh3 is in httpx's dependency tree on Windows, but we fall back to a pure-Python
implementation if it isn't importable.

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1

## Run only this check

```
wpsecscan --target https://example.com --only favicon_hash
```
