# WPSecScan installation matrix

Round-64 #113 — every distribution channel we support. Pick the one
that fits your platform.

## Windows

### winget (recommended, Windows 11)
```powershell
winget install Bryan.WPSecScan
```

### Chocolatey
```powershell
choco install wpsecscan
```

### Direct .exe download
1. Download `wpsecscan.exe` + `wpsecscan-gui.exe` from
   <https://github.com/bryanflowers/wpsecscan/releases/latest>
2. Drop into `C:\Tools\` (or any folder on your PATH).
3. Verify signature:
   ```powershell
   cosign verify-blob wpsecscan.exe `
     --signature wpsecscan.exe.sig `
     --certificate wpsecscan.exe.pem `
     --certificate-identity-regexp 'https://github.com/bryanflowers/wpsecscan' `
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

### MSI installer
NSIS installer at `installer/wpsecscan-setup.exe`.

## macOS

### Homebrew (recommended)
```bash
brew install bryanflowers/tap/wpsecscan
```

### pip
```bash
pip install wpsecscan
```

## Linux

### Snap
```bash
sudo snap install wpsecscan
```

### Flatpak
```bash
flatpak install flathub com.wpsecscan.Scanner
```

### Arch (AUR)
```bash
yay -S wpsecscan
```

### Debian / Ubuntu
```bash
pip install wpsecscan
# Or build a .deb yourself via stdeb.
```

### Fedora / RHEL
```bash
pip install wpsecscan
```

## Containers

### Docker
```bash
docker run --rm ghcr.io/bryanflowers/wpsecscan:2.2.0 \
  scan https://example.com
```

### Docker Compose
```bash
docker compose up -d
docker compose exec wpsecscan wpsecscan scan https://example.com
```

### Kubernetes
See `k8s/operator-scaffold.md`.

## From source

```bash
git clone https://github.com/bryanflowers/wpsecscan
cd wpsecscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
wpsecscan --demo
```

## Verifying

Every release ships SHA256SUMS.txt + Sigstore signatures + SLSA L3
provenance. See [verify-release.md](verify-release.md).

## Per-channel verification quirks

| Channel | Verifies as |
|---------|-------------|
| winget | Manifest SHA + ms-store curation |
| Chocolatey | Package SHA + community moderation |
| Homebrew | Tarball SHA |
| Snap | Snap Store review |
| Flatpak | Flathub review |
| AUR | Maintainer trust (us) |
| Docker | Sigstore cosign (recommended: `cosign verify`) |
| pip | PyPI 2FA + Sigstore (since PEP 740) |
| .exe direct | SLSA L3 + Sigstore (see verify-release.md) |
