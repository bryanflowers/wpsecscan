# WPSecScan installation matrix

Three channels exist: PyPI, the GitHub release assets, and a source
install. No other package-manager listing, container-registry image or
installer is published. Pick the one that fits your platform.

## pip (Windows, macOS, Linux)

```bash
pip install wpsecscan
wpsecscan --version
```

PyPI: <https://pypi.org/project/wpsecscan/>. Needs Python 3.10+.

## Windows binaries (no Python needed)

1. Download `wpsecscan.exe` and `wpsecscan-gui.exe` (each about 31 MB) from
   <https://github.com/bryanflowers/wpsecscan/releases/latest>
2. Drop them into `C:\Tools\` (or any folder on your PATH).
3. Verify them (the binaries are not code-signed, so SmartScreen will warn):
   ```powershell
   gh attestation verify wpsecscan.exe --owner bryanflowers
   ```
   The `cosign verify-blob` and `SHA256SUMS.txt` checks are in
   [verify-release.md](verify-release.md).

The release also carries the wheel, the sdist, `SHA256SUMS.txt`, the
`.sig`/`.pem` Sigstore files and `sbom.cyclonedx.json`.

## From source

```bash
git clone https://github.com/bryanflowers/wpsecscan
cd wpsecscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
wpsecscan --demo
```

## Containers (build it yourself)

The repository has a `Dockerfile` and a `docker-compose.yml`. No image is
published, so build locally:

```bash
docker build -t wpsecscan .
docker run --rm wpsecscan https://example.com
```

With compose, edit the target in `docker-compose.yml` (or a `.env` file)
and run `docker compose run --rm wpsecscan`.

## Verifying

Every release ships `SHA256SUMS.txt`, Sigstore signatures and GitHub
build-provenance attestations. See [verify-release.md](verify-release.md).

## Per-channel verification

| Channel | Verifies as |
|---------|-------------|
| pip | PyPI 2FA + Sigstore (since PEP 740) |
| .exe / wheel / sdist direct | `gh attestation verify` + Sigstore `.sig`/`.pem` + `SHA256SUMS.txt` (see verify-release.md) |
| source | `git` tag, or rebuild and compare (see verify-release.md) |
