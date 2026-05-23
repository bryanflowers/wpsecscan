# Build both binaries:
#   dist\wpsecscan.exe              - CLI (console)
#   dist\wpsecscan-gui.exe   - GUI (windowed, no console)
# Usage:  .\build.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path ".venv")) {
    Write-Host "[build] creating venv..." -ForegroundColor Cyan
    python -m venv .venv
}

$py  = Join-Path $root ".venv\Scripts\python.exe"
$pip = Join-Path $root ".venv\Scripts\pip.exe"

Write-Host "[build] installing deps..." -ForegroundColor Cyan
& $pip install --upgrade pip
& $pip install -r requirements.txt pyinstaller

Write-Host "[build] building CLI (wpsecscan.exe)..." -ForegroundColor Cyan
& $py -m PyInstaller --noconfirm --onefile --name wpsecscan `
    --add-data "wpsecscan\data;wpsecscan\data" `
    --add-data "scripts\add-defender-exclusion.ps1;scripts" `
    --collect-submodules wpsecscan `
    --collect-submodules openpyxl `
    --version-file version_info.txt `
    run.py

Write-Host "[build] building GUI (wpsecscan-gui.exe)..." -ForegroundColor Cyan
& $py -m PyInstaller --noconfirm --onefile --windowed --name wpsecscan-gui `
    --add-data "wpsecscan\data;wpsecscan\data" `
    --add-data "scripts\add-defender-exclusion.ps1;scripts" `
    --collect-submodules wpsecscan `
    --collect-submodules openpyxl `
    --version-file version_info.txt `
    run_gui.py

foreach ($name in @("wpsecscan.exe", "wpsecscan-gui.exe")) {
    $exe = Join-Path $root "dist\$name"
    if (Test-Path $exe) {
        $size = [Math]::Round((Get-Item $exe).Length / 1MB, 1)
        Write-Host "[build] OK -> $exe  ($size MB)" -ForegroundColor Green
    } else {
        Write-Host "[build] MISSING: $exe" -ForegroundColor Red
    }
}
