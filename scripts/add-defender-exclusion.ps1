# Add Windows Defender exclusion for WPSecScan.
#
# Why this is needed:
#   WPSecScan ships exploit-detection signatures for known webshells (China
#   Chopper, c99, r57, etc.). To DETECT those patterns on your sites, the
#   scanner has to contain references to them. Defender's heuristic engine
#   pattern-matches the .exe and flags it as `Backdoor:JS/Chopper.GG!dha`.
#   This is a documented false positive on offensive-security tools
#   (sqlmap, Metasploit, nuclei, gophish all trip the same kind of heuristic).
#
# What this script does:
#   - Adds the dist\ folder containing wpsecscan.exe + wpsecscan-gui.exe
#     to the Defender exclusion list, so future scans won't quarantine them.
#   - Requires admin rights (Defender CmdLet is admin-only).
#
# What this script does NOT do:
#   - It does NOT disable Defender.
#   - It does NOT add ALL of WPSecScan's working directories to exclusion —
#     only the directory containing the .exe binaries.
#   - It does NOT touch any other Defender policy.

[CmdletBinding()]
param(
    [string] $ExePath
)

$ErrorActionPreference = "Stop"

# Resolve the .exe path — caller can pass --, or we auto-detect siblings.
if (-not $ExePath) {
    # Try to find dist\wpsecscan.exe from current dir + script dir
    $candidates = @(
        (Join-Path $PSScriptRoot "..\dist\wpsecscan.exe"),
        (Join-Path $PSScriptRoot "..\..\dist\wpsecscan.exe"),
        (Join-Path (Get-Location) "dist\wpsecscan.exe"),
        (Join-Path (Get-Location) "wpsecscan.exe"),
        "C:\Program Files\WPSecScan\wpsecscan.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExePath = (Resolve-Path $c).Path; break }
    }
}
if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Host "ERROR: couldn't locate wpsecscan.exe. Pass -ExePath C:\path\to\wpsecscan.exe" -ForegroundColor Red
    exit 1
}

$ExeDir = Split-Path -Parent (Resolve-Path $ExePath)
Write-Host "WPSecScan binary directory: $ExeDir"

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Re-launching with admin rights (UAC will prompt)..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-ExePath", $ExePath
    )
    exit 0
}

# Verify Defender CmdLets are available (some versions of Windows don't have them — Pro/Enterprise expected)
if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Defender PowerShell CmdLets not available on this Windows edition." -ForegroundColor Red
    Write-Host "Add the exclusion manually: Windows Security -> Virus & threat protection -> Manage settings -> Exclusions" -ForegroundColor Yellow
    Write-Host "Then add this folder: $ExeDir" -ForegroundColor Yellow
    exit 1
}

try {
    # Folder exclusion covers both wpsecscan.exe and wpsecscan-gui.exe
    Add-MpPreference -ExclusionPath $ExeDir -ErrorAction Stop
    # Belt-and-braces: also exclude the specific .exe files in case the folder rule isn't honored
    foreach ($name in @("wpsecscan.exe", "wpsecscan-gui.exe")) {
        $p = Join-Path $ExeDir $name
        if (Test-Path $p) {
            Add-MpPreference -ExclusionProcess $p -ErrorAction Continue
        }
    }
    Write-Host ""
    Write-Host "[OK] Added Defender exclusion for: $ExeDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "To remove later, run as admin:" -ForegroundColor Cyan
    Write-Host "  Remove-MpPreference -ExclusionPath '$ExeDir'" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "If Defender already quarantined a file, restore it from:" -ForegroundColor Yellow
    Write-Host "  Windows Security -> Virus & threat protection -> Protection history" -ForegroundColor Yellow
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
