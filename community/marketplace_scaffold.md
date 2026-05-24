# WPSecScan check marketplace — design scaffold

Round-64 #124 — third parties can publish + share custom checks via a
marketplace. Not yet implemented; this is the design.

## Concept

A check is already a `.py` file that drops into `~/.wpsecscan/plugins/`.
The marketplace just adds:
- Discovery (browsable index)
- Signature verification (Sigstore keyless)
- Versioning (semver per check)
- Per-check trust score (community-voted)

## Index format

`https://marketplace.wpsecscan.com/index.json`:

```json
{
  "version": "1.0",
  "checks": [
    {
      "id": "shopify_plus_audit",
      "title": "Shopify Plus shop audit",
      "author": "vendor-x",
      "version": "1.2.0",
      "url": "https://github.com/vendor-x/shopify-plus-audit-wpsec/releases/download/v1.2.0/shopify_plus_audit.py",
      "signature_url": "https://github.com/vendor-x/.../shopify_plus_audit.py.sig",
      "certificate_url": "https://github.com/vendor-x/.../shopify_plus_audit.py.pem",
      "categories": ["commerce", "shopify"],
      "license": "MIT",
      "min_wpsecscan_version": "2.2.0",
      "trust_score": 4.7,
      "downloads_30d": 1240
    }
  ]
}
```

## Client commands

```bash
wpsecscan marketplace list
wpsecscan marketplace search shopify
wpsecscan marketplace install shopify_plus_audit
wpsecscan marketplace verify shopify_plus_audit
```

## Trust model

- Every check is signed with Sigstore keyless (same flow as our .exes).
- Verification at install time enforces the cert chain back to the
  published author identity.
- Authors can be banned by community vote (50+ Trust Score votes
  needed); banned authors are removed from the index.
- The local client refuses to load unsigned checks unless
  `--allow-unsigned` is passed.

## Out of scope (today)

- Paid checks (Stripe Connect; defer)
- Auto-update of installed checks (defer; security trade-off)
- Per-check telemetry sent to author (defer; privacy)

## Why not just a GitHub topic?

Because authors need signed releases + a central trust score + uniform
versioning. A GitHub-topic search would return any repo with that tag,
including malicious typosquats.
