# Install + uninstall

## Windows (binary — recommended)

1. Download `wpsecscan-setup-1.9.0.exe` (or `wpsecscan.exe` + `wpsecscan-gui.exe`) from the [latest release](https://github.com/bryanflowers/wpsecscan/releases/latest).
2. Run the installer. The wizard offers:
   - Install location (default `C:\Program Files\WPSecScan`)
   - "Run at Windows startup" checkbox
   - "Add to PATH" checkbox
3. Done. `wpsecscan` is on your PATH; `WPSecScan` is in the Start Menu.

### Defender false-positive
The .exe is unsigned (cost-saving choice). Defender may flag pattern-detection
strings as suspicious. To allow:

```
powershell -ExecutionPolicy Bypass -File "C:\Program Files\WPSecScan\add-defender-exclusion.ps1"
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

### Windows installer
Settings → Apps → WPSecScan → Uninstall. The wizard offers to also remove
`~/.wpsecscan/` config (off by default).

### pip
```
pip uninstall wpsecscan
rm -rf ~/.wpsecscan        # optional — removes config + history + AI cost log
```
