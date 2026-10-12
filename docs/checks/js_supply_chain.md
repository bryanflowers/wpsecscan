---
id: js_supply_chain
title: "External JS supply-chain audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Other"
words: 176
---

# External JS supply-chain audit

**check_id**: `js_supply_chain`
**aggressive**: no
**category**: Other
**max severity**: high
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain

## What it does

JS + CSS supply-chain inventory.

Inventories every external host serving JS and stylesheets to your pages,
and flags unpinned references (no SRI hash). Both `<script src>` and
`<link rel=stylesheet>` are an SRI risk — a CDN compromise can poison your
JS via either vector.

Risky hosts (raw GitHub, unfamiliar CDNs) get higher severity than well-known
ones (jsdelivr, unpkg with SRI).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | JS loaded from high-risk host: ⟨host⟩ | Replace with a versioned-and-pinned CDN (jsdelivr.net, unpkg.com) using an integrity hash. Or self-host the script after pinning to a specific commit hash. |
| high/medium | ⟨unpinned⟩ ⟨kinds⟩ reference(s) to ⟨host⟩ without SRI hash | Add Subresource Integrity hashes to every external asset: &lt;script src="..." integrity="sha384-..." crossorigin="anonymous"&gt;&lt;/script&gt; &lt;link rel="stylesheet" href="..." integrity="sha384-..." crossorigin="anonymous"&gt; Generate hashes via https://www.srihash.org |
| info | External JS+CSS hosts inventory: ⟨count⟩ unique host(s) | No action needed for the inventory itself — see follow-up findings for risky entries. |
| info | No external JS / CSS hosts loaded | No action needed. |

## Evidence the check records

- No external JS / CSS hosts loaded: All &lt;script src&gt; and &lt;link rel=stylesheet&gt; references resolve to the same origin.
- JS loaded from high-risk host: ⟨host⟩: ⟨value⟩ &lt;script src=&gt; reference(s) to ⟨host⟩ Samples: ⟨value⟩ ⟨host⟩ serves raw repository content — any commit by the repo owner replaces your production JS instantly. There's no review gate.
- ⟨unpinned⟩ ⟨kinds⟩ reference(s) to ⟨host⟩ without SRI hash: ⟨host⟩: ⟨unpinned⟩/⟨value⟩ references have no `integrity=` attribute. Asset kinds present: ⟨kinds⟩ Samples: ⟨value⟩ Without SRI, the CDN can serve any modified content (compromised, swapped, replaced). This applies to BOTH &lt;script src&gt; and &lt;link rel=stylesheet&gt; — a poisoned stylesheet can execute behavior:url(), serve tracking pixels, or use @import to fetch attacker JS.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/ | grep -oE '<script[^>]*src="[^"]+"[^>]*>' | head -40
# Look for missing integrity= attributes and unfamiliar hosts.
# Generate an SRI hash for an external script:
curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
# Add it to the tag: <script src="..." integrity="sha384-..." crossorigin="anonymous">
# Polyfill.io / bootcdn.net etc. — REMOVE entirely or self-host.
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SA-9
- **compliance_map / iso_27001**: A.5.19
- **compliance_v2 / hitrust**: 06.j
- **compliance_v2 / cmmc**: SR.L2-3.17.1
- **compliance_v2 / nist_csf**: ID.SC-04
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.5.21

## References

- https://www.srihash.org

## Run only this check

```
wpsecscan only js_supply_chain https://example.com
```

`only` runs this check alone and prints its findings.
