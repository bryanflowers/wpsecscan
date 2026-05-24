# Installer build

## NSIS (.exe wizard — recommended for end users)

1. Install NSIS 3.x: https://nsis.sourceforge.io/Download
2. Install the EnVar plugin (drop `EnVar.dll` into NSIS's `Plugins\x86-unicode\`): https://nsis.sourceforge.io/EnVar_plug-in
3. From repo root: `makensis installer/wpsecscan-setup.nsi`
4. Output: `dist/wpsecscan-setup-1.9.0.exe`

The installer offers:
- Install location
- Add to PATH (off by default)
- Run GUI at Windows startup (off by default — adds HKCU Run reg value)
- Register weekly auto-scan task (off by default — adds schtasks entry)
- Add Defender exclusion (off by default — silently runs the bundled ps1)

Uninstaller is registered with Add/Remove Programs. On uninstall, it
prompts before wiping `%USERPROFILE%\.wpsecscan\` (default: keep).

## WiX MSI (enterprise)

1. Install WiX 4 or 5: `dotnet tool install --global wix`
2. From repo root: `wix build installer/wpsecscan.wxs -arch x64 -o dist/wpsecscan-1.9.0.msi`
3. Deploy via group policy or `msiexec /i wpsecscan-1.9.0.msi /quiet`

The MSI is intentionally minimal — it installs files + start-menu shortcut.
Use NSIS for end-user installs (richer UI + autostart options).

## Both require prior PyInstaller build

Run `python -m PyInstaller wpsecscan.spec wpsecscan-gui.spec` first, or
re-run `build.ps1`. Output binaries land in `dist/` where the installers
expect them.
