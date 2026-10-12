---
id: db_trigger_audit
title: "MySQL trigger audit via companion plugin (#53)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 99
---

# MySQL trigger audit via companion plugin (#53)

**check_id**: `db_trigger_audit`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: critical
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1546 — Event Triggered Execution
**CWE**: CWE-89
**D3FEND**: D3-FCR

## What it does

Database trigger audit (companion-plugin assisted).

Round-64 #53 — attackers sometimes install MySQL triggers as a stealth
persistence mechanism (fires on a normal write, runs arbitrary SQL). We
can't enumerate triggers remotely without DB access; the companion
plugin exposes `/wp-json/wpsecscan-companion/v1/triggers` which returns
the trigger list. Without the companion, this check is a no-op +
recommends installing it.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Suspicious MySQL trigger: ⟨name⟩ | This trigger fires on a normal table write and may be running arbitrary code. Run in MySQL: SHOW TRIGGERS; DROP TRIGGER &lt;name&gt;; Then audit for the entry-point that allowed an attacker to install the trigger (stolen DB creds, SQLi). |
| info | Companion plugin present but DB-trigger endpoint requires auth | Configure the companion plugin's shared secret in wpsecscan sites config so this check can authenticate. |
| info | No database triggers installed (clean) | Re-run periodically; triggers can be installed via stolen DB creds even without WP code access. |
| info | ⟨count⟩ DB trigger(s) — none matched malicious patterns | Triggers may be legitimate; review each in MySQL: SHOW CREATE TRIGGER &lt;name&gt;. |

## Evidence the check records

- Companion plugin present but DB-trigger endpoint requires auth: GET /wp-json/wpsecscan-companion/v1/triggers -&gt; ⟨value⟩
- No database triggers installed (clean): Companion returned ⟨count⟩ triggers
- ⟨count⟩ DB trigger(s) — none matched malicious patterns: Triggers: ⟨value⟩
- Suspicious MySQL trigger: ⟨name⟩: Trigger body contains: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 10.2
- **compliance_map / nist_800_53**: AU-2
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan only db_trigger_audit https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
