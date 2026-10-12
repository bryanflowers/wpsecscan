---
id: security_txt
title: "security.txt (RFC 9116) audit"
severity_max: low
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 53
---

# security.txt (RFC 9116) audit

**check_id**: `security_txt`
**aggressive**: no
**category**: File & directory exposure
**max severity**: low
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

security.txt / .well-known endpoint audit (RFC 9116).

Modern sites should publish /.well-known/security.txt with a security
contact + scope statement. Also probes for /.well-known/change-password
(RFC 8615) and /humans.txt.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | No /.well-known/security.txt found (RFC 9116) | Publish a security.txt at /.well-known/security.txt. Use https://securitytxt.org to generate. Minimum content: Contact: mailto:security@yourdomain.com Expires: &lt;date 1 year out, ISO 8601&gt; Preferred-Languages: en Researchers reporting findings need a way to reach you. |
| info | security.txt present (good) | Verify Contact and Expires are current. |

## Evidence the check records

- security.txt present (good): GET ⟨value⟩ -&gt; 200 First 200 chars: ⟨value⟩
- No /.well-known/security.txt found (RFC 9116): Neither /.well-known/security.txt nor /security.txt returned a valid security.txt.

## Compliance mapping

- **compliance_map / pci_dss**: 12.10.1
- **compliance_map / nist_800_53**: IR-7
- **compliance_map / iso_27001**: A.5.24
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: IR.L2-3.6.2
- **compliance_v2 / nist_csf**: RS.CO-02
- **compliance_v2 / cis_v8**: 17.2
- **compliance_v2 / iso_27001_2022**: A.5.5

## References

- https://securitytxt.org

## Run only this check

```
wpsecscan only security_txt https://example.com
```

`only` runs this check alone and prints its findings.
