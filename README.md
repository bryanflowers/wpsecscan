# WPSecScan CVE data feed

This branch is rewritten **nightly at 02:00 UTC** by
`.github/workflows/cve-feed.yml` on the `main` branch.
It contains a single file, `vuln-db.json`, which is the
merged + deduped union of every free CVE source we know
about (Wordfence, OSV.dev, GHSA, Mitre CVE List, NVD,
WPVulnerability.com, Patchstack RSS, CIRCL).

End-user scanners pull this via:

    https://raw.githubusercontent.com/bryanflowers/wpsecscan/data-feed/vuln-db.json

Inspect the timestamp + per-source counts in the first ~100
bytes of `vuln-db.json` to confirm freshness.

See `docs/data-sources.md` on the `main` branch for the
full source list + licences.
