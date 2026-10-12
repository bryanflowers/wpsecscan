---
id: helm_compose_leak
title: "Helm/compose/k8s manifest exposure (#68)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 86
---

# Helm/compose/k8s manifest exposure (#68)

**check_id**: `helm_compose_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-538
**D3FEND**: D3-FCR

## What it does

Helm / docker-compose / k8s manifest exposure scan.

Round-64 #68 — WP sites deployed via Helm + k8s sometimes leak the
values.yaml / docker-compose.yml in the docroot (someone runs
`helm template` and forgets to .gitignore the output, or a
docker-compose.yml ends up under public_html). These files commonly
contain image SHAs, environment variables (=&gt; secrets), and internal
service names that aid lateral movement.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | ⟨name⟩ leaked in ⟨path⟩ | ROTATE the ⟨name⟩ immediately. Move secrets out of the YAML into a separate Secret object (k8s) or .env (compose). |
| medium | ⟨kind⟩ file exposed at ⟨path⟩ | Block ⟨kind⟩ files publicly. These leak image SHAs, service names + ports, env-var keys (and sometimes values). Add a deny rule in your web-server config matching *.yml + *.yaml above the docroot. |

## Evidence the check records

- ⟨kind⟩ file exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes); shape: ⟨kind⟩
- ⟨name⟩ leaked in ⟨path⟩: Pattern ⟨name⟩ matched in ⟨path⟩

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only helm_compose_leak https://example.com
```

`only` runs this check alone and prints its findings.
