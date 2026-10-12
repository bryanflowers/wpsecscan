# Proof helpers (`--prove`)

`--prove` (`-P`) turns "the scanner thinks this finding is real" into a small,
redacted evidence artifact. There are five helpers, defined in the `PROVERS`
table in `wpsecscan/prove.py`. Each one serves one aggressive check id and
collects one narrow fact.

| Check id | What is verified | Evidence kept |
|---|---|---|
| `sqli` | That the injection vector found by detection works, shown by reading the database version only. | Version string. No tables, schema or user data. |
| `path_traversal` | That the file read seen during detection is repeatable. It does not move on to other files. | A short, redacted preview of the same read (200-byte cap). |
| `ssrf` | That the vulnerable endpoint will fetch a loopback address. Loopback only: no cloud-metadata or private-range targets. | HTTP status and a 100-character body preview. |
| `xss_reflected` | That the reflection seen during detection repeats on a second request. Nothing is submitted. | A yes/no repeatability flag and the marker. |
| `open_redirect` | Nothing extra. Detection already shows the redirect, so the helper does not send another request. | A note saying so. |

## Read-only

- Every SQL string is a module-level constant, never built from input.
  `_assert_select_only` rejects multi-statement SQL, anything over 600 bytes,
  and any write, schema, file or transaction keyword. It runs on every
  constant when the module is imported.
- Helpers make single read requests and never write to the scanned site.
- Output goes through a redaction step before it reaches a report, so database
  passwords and API keys are masked.
- Anything beyond this (table dumps, hash extraction, file writes, code
  execution) is out of scope. Use a dedicated tool for that, on a target you
  are authorised to test.

## Requirements

- `--prove` requires `--aggressive`. Without a confirmed aggressive finding
  there is nothing to prove.
- `--prove` is single-target. It refuses `--file` batch mode with exit code 64.
- Aggressive mode needs ownership consent for the target host: `--owned`, the
  `WPSECSCAN_OWNED_TARGETS` environment variable, or `wpsecscan owned add <host>`.
  With no consent recorded, the scan is downgraded to passive, so there are no
  aggressive findings and nothing to prove. Consent logic lives in
  `wpsecscan/consent.py`.

Evidence is written under the scan's output directory as `proof-<check_id>.txt`.
