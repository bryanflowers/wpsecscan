# Distribution manifests

Drop-in package definitions for shipping WPSecScan via OS / language
package managers. **None of these are auto-published — each requires the
respective marketplace account.** Update the version + SHA256 every release,
then publish via the steps below.

## Chocolatey (Windows)
```
choco install wpsecscan      # once published
```
Build + push:
```
cd distribution/chocolatey
choco pack
choco push wpsecscan.2.0.0.nupkg --source https://push.chocolatey.org/
```
Account: https://chocolatey.org → publish your package.

## Winget (Windows)
```
winget install WPSecScan.Bryan
```
Submit:
```
gh repo fork microsoft/winget-pkgs
# Copy the YAML to manifests/w/WPSecScan/Bryan/2.0.0/
# PR the change to microsoft/winget-pkgs
```
Update SHA256 by running `Get-FileHash dist\wpsecscan.exe`.

## Homebrew (macOS / Linux)
```
brew tap bryanflowers/tap
brew install wpsecscan
```
Setup:
1. Create a public repo `bryanflowers/homebrew-tap` (must use the `homebrew-` prefix)
2. Drop the `.rb` formula from `distribution/homebrew/` into `Formula/`
3. Update SHA256 with: `shasum -a 256 <github archive tarball>`

## AppImage (Linux portable)
```
appimage-builder --recipe distribution/appimage/AppImageBuilder.yml
```
Output: `WPSecScan-2.0.0-x86_64.AppImage` — chmod +x and run.

## Snap (Ubuntu)
```
cd distribution/snap
snapcraft
snapcraft push wpsecscan_2.0.0_amd64.snap --release=stable
```
Account: https://snapcraft.io/account → register the name.

## Flatpak (Linux desktop)
```
flatpak-builder build distribution/flatpak/com.github.bryanflowers.wpsecscan.yml
```
Publish to flathub via https://github.com/flathub/flathub.

## NSIS + MSI installers

See [installer/README.md](../installer/README.md) — pre-existing.

## ARM64 builds

PyInstaller produces native binaries for the build host. To ship Windows-on-ARM
or Apple Silicon:

```bash
# On a Windows ARM64 machine:
.\build.ps1
mv dist\wpsecscan.exe dist\wpsecscan-arm64.exe

# On Apple Silicon:
.venv/bin/pyinstaller --onefile --windowed run.py
# Output is universal2 if built with a universal Python; otherwise arm64-only.
```

GitHub Actions runners that ship ARM64:
- `windows-11-arm` (Microsoft preview)
- `macos-14` and later (Apple Silicon)
- `ubuntu-22.04-arm` (preview)
