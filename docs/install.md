# Install + uninstall

## Windows (binary — recommended)

1. Download `wpsecscan.exe` and `wpsecscan-gui.exe` from the [latest release](https://github.com/bryanflowers/wpsecscan/releases/latest). There is no installer; the two files are standalone.
2. Copy them into a folder on your PATH (e.g. `C:\Tools\`).
3. Optionally check them first: see [verify-release.md](verify-release.md).

### Defender false-positive
The .exe is unsigned (cost-saving choice). Defender may flag pattern-detection
strings as suspicious. The repository ships a helper that adds an exclusion
(run from an admin PowerShell, from a source checkout):

```
powershell -ExecutionPolicy Bypass -File scripts\add-defender-exclusion.ps1
```

## Windows (pip)

```
pip install wpsecscan
wpsecscan --version
```

## macOS / Linux (pip)

```
python -m pip install --user wpsecscan
wpsecscan --version
```

For the headless DOM-XSS check + screenshots:
```
python -m pip install --user 'wpsecscan[browser]'
playwright install chromium
```

## From source

```
git clone https://github.com/bryanflowers/wpsecscan
cd wpsecscan
pip install -e '.[all]'
pytest -q
```

## Uninstall

### Windows binaries
Delete `wpsecscan.exe` and `wpsecscan-gui.exe`. Remove `~/.wpsecscan/`
too if you want to drop config and history.

### pip
```
pip uninstall wpsecscan
rm -rf ~/.wpsecscan        # optional — removes config + history + AI cost log
```
