---
id: plugin_cemetery
title: "Abandoned-plugin detector (wp.org last_updated)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 235
---

# Abandoned-plugin detector (wp.org last_updated)

**check_id**: `plugin_cemetery`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1195 — Supply Chain Compromise

## What it does

Abandoned-plugin detector — flags plugins that haven't been updated in
years, BEFORE they pick up a CVE.

Cross-references each enumerated plugin slug against the WordPress.org
plugin info endpoint and reports `last_updated`. The thresholds:
  - &gt;2 years stale  -&gt; medium  "long-stale plugin (no CVE yet)"
  - &gt;4 years stale  -&gt; high    "abandoned plugin (no security maintenance)"
  - removed from wp.org -&gt; high "delisted plugin (can't receive updates)"

This is orthogonal to plugin_cves: a plugin can be CVE-free today but
unmaintained, which is itself a forward-looking risk indicator. The
opposite is also true — a plugin with recent updates but a known CVE
already gets flagged by plugin_cves; the cemetery check stays quiet
there to avoid double-reporting.

Network: one GET per discovered plugin against
https://api.wordpress.org/plugins/info/1.0/{slug}.json (cached 24h
on disk under ~/.wpsecscan/cache/wporg/).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Plugin '⟨slug⟩' delisted from wp.org — cannot receive updates | Replace `⟨slug⟩` with an actively-maintained alternative or remove it from the site. Verify on https://wordpress.org/plugins/ search — if the listing is gone, do not reinstall. |
| high/medium | ⟨label⟩ | Audit whether the plugin is still doing useful work. If yes, find a maintained replacement (search wp.org for newer alternatives) or move the functionality to your own theme code. If no, deactivate + delete. |
| info | No abandoned or delisted plugins detected | No action. |
| info | Plugin cemetery check skipped — no plugins enumerated | No action. |

## Evidence the check records

- Plugin cemetery check skipped — no plugins enumerated: Nothing in ctx['shared']['plugins']; the plugins check found nothing.
- ⟨label⟩: wp.org last_updated: ⟨value⟩ Active installs: ⟨value⟩ Tested up to WP: ⟨value⟩ Requires WP: ⟨value⟩ Unmaintained plugins accumulate undisclosed vulnerabilities and stop tracking newer WP-core security model changes. The risk grows with time.
- No abandoned or delisted plugins detected: Checked ⟨count⟩ enumerated plugin(s); all have recent wp.org activity.
- Plugin '⟨slug⟩' delisted from wp.org — cannot receive updates: https://api.wordpress.org/plugins/info/1.0/⟨slug⟩.json -&gt; 404. Plugins are typically delisted because of an unpatched security issue or developer abandonment. The site cannot auto-update this plugin and won't be notified of new vulnerabilities.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.i
- **compliance_v2 / cmmc**: RA.L2-3.11.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## References

- https://api.wordpress.org/plugins/info/1.0/
- https://wordpress.org/plugins/

## Run only this check

```
wpsecscan only plugin_cemetery https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
