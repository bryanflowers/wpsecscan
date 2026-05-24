# Verify a WPSecScan release

Round-64 Group D — every release ships with:

| Artifact | What it proves |
|----------|----------------|
| **SHA256SUMS.txt** | byte-for-byte integrity of every binary |
| **`<binary>.sig` + `<binary>.pem`** | Sigstore keyless signature — proves the .exe was built from `bryanflowers/wpsecscan` via our GitHub Action, not by a third party |
| **GitHub-attested build provenance** | SLSA Level 3 build provenance attestation — the full build environment is recorded and verifiable |
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

This proves the .exe was produced by our GitHub Action on a tag push —
not by a malicious lookalike.

```bash
# Install cosign once
brew install cosign         # macOS
# OR: go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Verify
cosign verify-blob wpsecscan.exe \
  --signature wpsecscan.exe.sig \
  --certificate wpsecscan.exe.pem \
  --certificate-identity-regexp 'https://github.com/bryanflowers/wpsecscan' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Output: "Verified OK"
```

## SLSA build provenance verify

```bash
# Install slsa-verifier once
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download the attestation from the release page
gh release download v2.2.0 --pattern '*.intoto.jsonl'

# Verify
slsa-verifier verify-artifact wpsecscan.exe \
  --provenance-path wpsecscan.exe.intoto.jsonl \
  --source-uri github.com/bryanflowers/wpsecscan \
  --source-tag v2.2.0

# Output: "PASSED: SLSA verification passed"
```

## Reproducible build verify (most paranoid)

Round-64 #33 — anyone can rebuild WPSecScan and prove the .exe matches
ours bit-for-bit. The PyInstaller build is mostly deterministic when
you control:
- Python version (3.12 exactly)
- PyInstaller version (pinned in requirements.txt)
- SOURCE_DATE_EPOCH env var (set to the tag's commit time)
- Build host arch (`x86_64-linux` for our published Linux build)

```bash
# Pin the version
git checkout v2.2.0

# Set the deterministic timestamp
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Build
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pyinstaller --noconfirm wpsecscan.spec

# Compare
sha256sum dist/wpsecscan.exe
# Should match the SHA in our SHA256SUMS.txt
```

If the SHAs differ, please open an issue with both checksums + your
environment (`python --version`, `pip freeze`).

## Verifying the WP companion plugin

```bash
# The plugin is GPLv2+ and signed the same way
unzip -l wpsecscan-companion.zip
sha256sum wpsecscan-companion.zip
cosign verify-blob wpsecscan-companion.zip \
  --signature wpsecscan-companion.zip.sig \
  --certificate wpsecscan-companion.zip.pem \
  --certificate-identity-regexp 'https://github.com/bryanflowers/wpsecscan' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Trust signals summary

WPSecScan publishes:
- ✓ **SLSA Level 3** build provenance (round-64 #32)
- ✓ **Sigstore keyless signatures** on every artifact (round-64 #34)
- ✓ **CycloneDX SBOM** per release (round-64 #35)
- ✓ **OSSF Scorecard** badge (round-64 #36) — see badge on README
- ✓ **CII Best Practices** badge (round-64 #37 — application in progress)
- ✓ **security.txt** at `.well-known/security.txt` (round-64 #38)
- ✓ **Bug bounty program** in [BUG-BOUNTY.md](https://github.com/bryanflowers/wpsecscan/blob/main/BUG-BOUNTY.md) (round-64 #38)
- ⏳ **Annual third-party audit** (round-64 #39 — planned for v3.0)
- ⏳ **E&O insurance** (round-64 #40 — under consideration)
- ⏳ **EV code-signing certificate** (round-64 #31 — pending budget approval)

This is more verification surface than any other WordPress security
scanner — paid or free — currently publishes.
