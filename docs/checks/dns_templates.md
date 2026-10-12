---
id: dns_templates
title: "DNS templates (#13)"
severity_max: info
severity_dynamic: true
aggressive: false
category: "DNS, email & infra"
words: 147
---

# DNS templates (#13)

**check_id**: `dns_templates`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: info (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1071.004 — DNS Application Layer
**CWE**: CWE-693
**D3FEND**: D3-DNSTI

## What it does

#13 (from nuclei) — DNS template support (subset).

nuclei templates can include `dns:` blocks alongside `http:`. We add
a minimal DNS template runner that supports:

  - record types: A, AAAA, MX, TXT, NS, CNAME
  - matchers: word, regex (against the joined record values)
  - the "{{Host}}" variable substituted with the target's hostname

Templates in `~/.wpsecscan/templates/*.yaml` may include a `dns:` block:

    dns:
      - name: "{{Host}}"
        type: TXT
        matchers:
          - type: word
            words: ["v=spf1"]

Uses Python stdlib's socket + a manual DNS-query implementation for TXT/MX
to avoid taking on dnspython as a hard dep. For A / AAAA we use
socket.getaddrinfo. CNAME / NS / TXT / MX use a tiny built-in resolver.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | DNS templates skipped (PyYAML not installed) | No action. |
| info | DNS templates — none in ~/.wpsecscan/templates/ | No action. |
| varies | [DNS template] ⟨name⟩ | — |

## Evidence the check records

- DNS templates skipped (PyYAML not installed): Install pyyaml to enable.
- DNS templates — none in ~/.wpsecscan/templates/: No template included a `dns:` block.
- [DNS template] ⟨name⟩: Query ⟨qtype⟩ ⟨qname⟩ matched template '⟨value⟩'. Records: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CA.L2-3.12.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.5
- **compliance_v2 / iso_27001_2022**: A.5.36

## Run only this check

```
wpsecscan only dns_templates https://example.com
```

`only` runs this check alone and prints its findings.
