---
id: source_maps
title: "Source-map exposure"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 129
---

# Source-map exposure

**check_id**: `source_maps`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials in Files

## What it does

Source-map exposure check.

Scans response bodies for `//# sourceMappingURL=...` comments and probes the
referenced `.map` files. A served .map exposes the full pre-minified JS source
(including bundled credentials, internal API paths, debug logging).

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨count⟩ source-map file(s) served — full client source exposed | Stop publishing source maps to production. In your build pipeline: - webpack: `devtool: false` (or `hidden-source-map` if you want maps locally) - vite: `build.sourcemap: false` - rollup: remove the sourcemap plugin from the prod config If maps are required for production debugging (Sentry, Datadog), use 'hidden-source-map' so the comment isn't published — only the sourcemap-uploader has access to it. |
| low | sourceMappingURL comments present in ⟨count⟩ JS file(s) — maps not currently served but comments leak the path | Strip sourceMappingURL comments in production builds. Use `hidden-source-map` devtool option. |
| info | No source-map exposure detected | No action needed. |

## Evidence the check records

- No source-map exposure detected: Probed ⟨count⟩ HTML pages and up to 20 JS files; no `//# sourceMappingURL=` comments led to served .map files.
- ⟨count⟩ source-map file(s) served — full client source exposed: JS source maps reachable: ⟨lines⟩ A served .map file contains the full pre-bundled source code — variable names, comments, internal API paths, and any secret accidentally bundled at build time. Attackers diff your .map against historical builds to extract removed secrets.
- sourceMappingURL comments present in ⟨count⟩ JS file(s) — maps not currently served but comments leak the path: References found: ⟨lines⟩

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/ | grep -oE 'sourceMappingURL=[^ "'\''*]+'
# Grep a JS bundle for the trailing comment:
curl -s https://example.com/<path-to-bundle>.js | tail -2
# Fix at the build tool: Webpack `devtool: false` for prod; Vite `build.sourcemap: false`; Next.js `productionBrowserSourceMaps: false`
# Or block at the web server: `location ~ \.map$ { deny all; }`
```

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 10.g
- **compliance_v2 / cmmc**: SI.L1-3.14.1
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 4.1
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan only source_maps https://example.com
```

`only` runs this check alone and prints its findings.
