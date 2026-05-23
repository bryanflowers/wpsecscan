# Code-signing the WPSecScan binaries

## Why

Without code-signing, Windows SmartScreen warns on first launch and
Defender heuristics tip towards quarantining. Signed binaries get a
publisher line in the UAC prompt and skip the SmartScreen warning
entirely (after enough downloads have built reputation).

## Cost

| Cert type | ~Cost / yr | SmartScreen behaviour |
|-----------|-----------|-----------------------|
| **EV code-signing**       | $300-400 | Trusted instantly (no reputation needed) |
| **OV code-signing**       | $80-150  | Needs reputation; SmartScreen warns until ~3000 downloads |
| Sigstore (open source)    | free     | Not honoured by SmartScreen — useful for SBOM provenance only |

For a security tool, **EV is the right call**. The publisher line in the
UAC prompt (`Verified publisher: <YourOrg>`) is the trust signal we want.

## Issuers (2025-2026 list)

- **SSL.com** — cheapest EV, USB-token shipped
- **Sectigo (formerly Comodo)** — well-established, cloud-HSM option
- **DigiCert** — most expensive, most respected
- **GlobalSign** — middle of the road

EV certs ship as a hardware USB token (FIPS-140-2 L2) — the private key
never leaves the token. Plug it in, type the PIN, sign.

## Signing the .exe (Windows, signtool)

After installing the Windows SDK:

```powershell
signtool sign /a /tr http://timestamp.sectigo.com /td sha256 /fd sha256 ^
  dist\wpsecscan.exe
signtool sign /a /tr http://timestamp.sectigo.com /td sha256 /fd sha256 ^
  dist\wpsecscan-gui.exe
```

The `/a` flag picks the first valid signing cert from the local store.
For HSM-backed (EV) certs, `signtool` walks the user through PIN entry.

## CI integration

For GitHub Actions on `windows-latest`:

```yaml
- name: Import code-signing certificate
  shell: powershell
  run: |
    [IO.File]::WriteAllBytes("cert.pfx", [Convert]::FromBase64String($env:WIN_CERT_B64))
    Import-PfxCertificate -FilePath cert.pfx -CertStoreLocation Cert:\CurrentUser\My `
      -Password (ConvertTo-SecureString -String $env:WIN_CERT_PASS -AsPlainText -Force)
  env:
    WIN_CERT_B64:  ${{ secrets.WIN_CERT_B64 }}
    WIN_CERT_PASS: ${{ secrets.WIN_CERT_PASS }}

- name: Sign binaries
  run: |
    signtool sign /a /tr http://timestamp.sectigo.com /td sha256 /fd sha256 `
      dist/wpsecscan.exe dist/wpsecscan-gui.exe
```

For EV certs in CI, you need a cloud-HSM option (DigiCert KeyLocker,
SSL.com eSigner). USB tokens don't work on hosted CI runners.

## Verification

After signing:

```powershell
signtool verify /pa /v dist\wpsecscan.exe
```

`/pa` uses default authentication; `/v` verbose mode shows the cert chain.

## Why this is documented but not implemented

Code-signing requires a paid cert tied to the publishing organisation.
It's a policy decision that lives in the build pipeline, not a code change.

The script + secrets must be added by the maintainer when they're ready to
publish signed releases. WPSecScan ships unsigned with a Defender exclusion
helper as a stopgap.
