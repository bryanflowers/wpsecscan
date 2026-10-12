---
id: sqli
title: "SQL injection probes"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 267
---

# SQL injection probes

**check_id**: `sqli`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Boolean / error / time-based SQL injection probes on common WP parameters.

Read-only payloads only — no DROP, INSERT, UPDATE, or destructive operators.
Detection is via:
  - SQL error fingerprints in response body
  - Differential response length between truthy ('1=1') vs falsy ('1=2') payloads
  - Time delta between baseline and SLEEP() payload (time-based blind)

Payloads are passed as raw strings via httpx `params=` so the HTTP client handles
percent-encoding once and correctly. (An earlier version pre-encoded payloads, which
httpx then percent-encoded again, corrupting the SQL fragment server-side.)

## Request footprint

The module contains 6 request call(s) to the target (GET x6). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | SQL error reflected from ⟨desc⟩ | Find the plugin/theme handling this parameter and switch all DB access to prepared statements via $wpdb-&gt;prepare(). Validate and cast inputs (intval() for IDs). If it's a third-party plugin, update or remove it. |
| critical | Time-based blind SQL injection in ⟨desc⟩ | Treat this as a critical incident. Take the vulnerable plugin/theme offline immediately, review server access/error logs for prior exploitation, and rotate any credentials that may have been read via UNION/SELECT chains. |
| high | Possible boolean-based SQL injection in ⟨desc⟩ | Verify manually with sqlmap or by reading the source. False positives are possible when sites randomize ad/widget content. If confirmed, locate the vulnerable code and switch to $wpdb-&gt;prepare(). |
| info | No SQL injection indicators on tested parameters | No action needed for the tested endpoints. Keep all plugins updated and prefer plugins from reputable maintainers. |
| info | Site response is unstable (variance ⟨noise⟩) — boolean SQLi detection unreliable | No action needed — informational. If you want boolean detection here, scan a static page like /sample-page/ instead of /. |

## Evidence the check records

- Possible boolean-based SQL injection in ⟨desc⟩: Differential lengths: baseline ?⟨param⟩=⟨baseline⟩ -&gt; ⟨bb⟩ bytes truthy ?⟨param⟩=⟨baseline⟩⟨QUOTE⟩⟨TRUTHY⟩ -&gt; ⟨bt⟩ bytes falsy ?⟨param⟩=⟨baseline⟩⟨QUOTE⟩⟨FALSY⟩ -&gt; ⟨bf⟩ bytes Truthy mirrors baseline (delta ⟨base_diff⟩); falsy diverges by ⟨diff⟩, suggesting the query is responding to attacker-controlled boolean logic.
- SQL error reflected from ⟨desc⟩: GET /?⟨param⟩=⟨baseline⟩⟨QUOTE⟩ -&gt; ⟨value⟩ Response contains MySQL error signature: '⟨sig⟩' This typically indicates a parameter is being concatenated into a query unsafely.
- Time-based blind SQL injection in ⟨desc⟩: Baseline request: ⟨value⟩ ms; SLEEP(3) payload: ⟨value⟩ ms. payload: ?⟨param⟩=⟨payload⟩ The 3-second delta strongly implies the database is executing attacker SQL.
- Site response is unstable (variance ⟨noise⟩) — boolean SQLi detection unreliable: 3 identical GETs to / varied by ⟨noise⟩ in body size. Dynamic ads/recommendations/A-B-tests typically cause this. Boolean-based SQLi probes will be skipped to avoid false positives; error- and time-based probes still run.
- No SQL injection indicators on tested parameters: Probed ⟨count⟩ common WP parameters with error/boolean/time payloads. WP core has long been hardened against these vectors; real-world WP SQLi usually lives in plugins. This is reassuring but not exhaustive.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/Top10/A03_2021-Injection/
- deep dive: https://portswigger.net/web-security/sql-injection
- video: https://www.youtube.com/watch?v=NoZSlYNAYzE

## Run only this check

```
wpsecscan only sqli https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
