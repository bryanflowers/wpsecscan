# Verify a WPSecScan release

Round-64 Group D — every release ships with:

| Artifact | What it proves |
|----------|----------------|
| **SHA256SUMS.txt** | byte-for-byte integrity of every binary |
| **`<binary>.sig` + `<binary>.pem`** | Sigstore keyless signature — proves the .exe was built from `bryanflowers/wpsecscan` via our GitHub Action, not by a third party |
| **GitHub build-provenance attestation** | GitHub artifact attestation recording the workflow run that produced the file; check with `gh attestation verify` |
| **`sbom.cyclonedx.json`** | Full Software Bill of Materials in CycloneDX format |

## Quick verify (recommended)

Just check the SHA256:

```bash
# Linux / macOS / Git Bash on Windows
sha256sum -c SHA256SUMS.txt
# OK if every line ends "OK"
```

PowerShell:

```powershell
Get-FileHash wpsecscan.exe -Algorithm SHA256
# compare the output against the matching line in SHA256SUMS.txt
```

## Full Sigstore verify (paranoid mode)

This proves the .exe was signed by our release-attestation GitHub Action
on a tag — not by a malicious lookalike.

```bash
# Install cosign once (e.g. via your OS package manager or the Sigstore
# release page), or build it with Go:
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Verify
cosign verify-blob wpsecscan.exe \
  --signature wpsecscan.exe.sig \
  --certificate wpsecscan.exe.pem \
  --certificate-identity-regexp 'https://github.com/bryanflowers/wpsecscan/\.github/workflows/release-attestation\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Output: "Verified OK"
```

## GitHub build-provenance attestation verify

Releases carry GitHub artifact attestations. The attestation workflow
attests the artifacts it downloads from the release; there is no
separate attestation file on the release page.

```bash
# Needs the GitHub CLI (gh)
gh attestation verify wpsecscan.exe --owner bryanflowers
```

A successful run prints the workflow and commit that produced the file.

## Reproducible build verify (most paranoid)

Round-64 #33 — anyone can rebuild WPSecScan and prove the .exe matches
ours bit-for-bit. The PyInstaller build is mostly deterministic when
you control:
- Python version (3.12 exactly)
- PyInstaller version (pinned in `build.ps1`)
- SOURCE_DATE_EPOCH env var (set to the tag's commit time)
- Build host arch (`x86_64-linux` for our published Linux build)

```bash
# Pin the version
git checkout v2.8.5

# Set the deterministic timestamp
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Build
python -m venv .venv
.venv/bin/pip install -e . pyinstaller==6.13.0
.venv/bin/pyinstaller --noconfirm wpsecscan.spec

# Compare
sha256sum dist/wpsecscan.exe
# Should match the SHA in our SHA256SUMS.txt
```

If the SHAs differ, please open an issue with both checksums + your
environment (`python --version`, `pip freeze`).

## The WP companion plugin

The plugin source lives in `wp-plugin/wpsecscan-companion/` in the
repository. It is not attached to releases as a separate asset, so there is
no companion-plugin signature to verify; review the source or use the
tagged repository checkout.

## Trust signals summary

WPSecScan publishes:
- ✓ **GitHub build-provenance attestations** on release artifacts (round-64 #32)
- ✓ **Sigstore keyless signatures** on every artifact (round-64 #34)
- ✓ **CycloneDX SBOM** per release (round-64 #35)
- ✓ **OSSF Scorecard** badge (round-64 #36) — see badge on README
- ✓ **CII Best Practices** badge (round-64 #37 — application in progress)
- ✓ **security.txt** at `.well-known/security.txt` (round-64 #38)
- ⏳ **Annual third-party audit** (round-64 #39 — planned for v3.0)
- ⏳ **E&O insurance** (round-64 #40 — under consideration)
- ⏳ **EV code-signing certificate** (round-64 #31 — pending budget approval)
