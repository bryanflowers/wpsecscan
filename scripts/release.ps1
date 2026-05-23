# scripts\release.ps1 — cut a new WPSecScan release.
#
# Usage:
#   .\scripts\release.ps1 -Version 1.5.1
#   .\scripts\release.ps1 -Version 1.6.0 -DraftOnly
#
# What it does:
#   1. Validates the version string + verifies git is clean
#   2. Runs pytest one last time
#   3. Bumps `version` in pyproject.toml
#   4. Adds a CHANGELOG.md entry stub (you fill in the body)
#   5. Builds both .exes via build.ps1
#   6. Tags + pushes
#   7. Creates a GitHub release (via `gh`) and uploads the .exes
#
# Requires:  gh (GitHub CLI), git, python venv at .venv, build.ps1
#
param(
    [Parameter(Mandatory=$true)][string]$Version,
    [switch]$DraftOnly,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if ($Version -notmatch '^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$') {
    throw "Version must look like 1.2.3 or 1.2.3-rc1; got '$Version'."
}

Write-Host "[release] target version: $Version" -ForegroundColor Cyan

# 1. git clean?
$status = git status --porcelain
if ($status) {
    throw "Working tree is dirty. Commit or stash before releasing.`n$status"
}

# 2. tests
if (-not $SkipTests) {
    Write-Host "[release] running pytest..." -ForegroundColor Cyan
    & "$root\.venv\Scripts\python.exe" -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "pytest failed — fix before releasing." }
}

# 3. bump version in pyproject.toml
$pp = Get-Content "$root\pyproject.toml" -Raw
$ppNew = $pp -replace '(?m)^version\s*=\s*"[^"]+"', "version = `"$Version`""
if ($ppNew -eq $pp) { throw "Couldn't find version line in pyproject.toml." }
Set-Content "$root\pyproject.toml" $ppNew -Encoding utf8 -NoNewline
Write-Host "[release] bumped pyproject.toml to $Version" -ForegroundColor Green

# 4. CHANGELOG.md stub — prepend an entry under [Unreleased]
$today = (Get-Date).ToString("yyyy-MM-dd")
$stub = "`n## [$Version] - $today`n`n### Added`n- (TODO: describe additions)`n`n### Fixed`n- (TODO: describe fixes)`n"
$cl = Get-Content "$root\CHANGELOG.md" -Raw
$cl = $cl -replace '(## \[Unreleased\][^\#]*)', "`$1$stub"
Set-Content "$root\CHANGELOG.md" $cl -Encoding utf8 -NoNewline
Write-Host "[release] added CHANGELOG.md stub for $Version (edit the body, then re-run)" -ForegroundColor Yellow

# Pause so the user can edit the changelog
Write-Host "`nEdit CHANGELOG.md now to fill in the $Version section, then press Enter to continue (Ctrl+C to abort)."
Read-Host | Out-Null

# 5. build .exes
Write-Host "[release] building .exes..." -ForegroundColor Cyan
& "$root\build.ps1"
if (-not (Test-Path "$root\dist\wpsecscan.exe") -or -not (Test-Path "$root\dist\wpsecscan-gui.exe")) {
    throw "Build did not produce both .exes."
}

# 6. commit + tag + push
Write-Host "[release] committing + tagging..." -ForegroundColor Cyan
git add pyproject.toml CHANGELOG.md
git commit -m "release: $Version"
git tag -a "v$Version" -m "wpsecscan $Version"
git push origin HEAD
git push origin "v$Version"

# 7. GitHub release
$notesFile = "$env:TEMP\release-notes-$Version.md"
@"
WPSecScan $Version — see [CHANGELOG.md](CHANGELOG.md#$($Version -replace '\.','')) for full notes.

## Downloads
- ``wpsecscan.exe`` — CLI scanner (Windows x64)
- ``wpsecscan-gui.exe`` — GUI scanner (Windows x64)

Both binaries are PyInstaller-built, single-file, no Python required.
First-launch may trigger SmartScreen until the binaries build reputation.

## Install
1. Download both ``.exe`` files
2. Drop them into a folder on your PATH
3. Run ``wpsecscan --help`` or double-click ``wpsecscan-gui.exe``

See [README.md](README.md) for the authorised-use disclaimer.
"@ | Set-Content $notesFile -Encoding utf8

$ghArgs = @("release", "create", "v$Version",
    "$root\dist\wpsecscan.exe", "$root\dist\wpsecscan-gui.exe",
    "--title", "WPSecScan $Version",
    "--notes-file", $notesFile)
if ($DraftOnly) { $ghArgs += "--draft" }

Write-Host "[release] creating GitHub release..." -ForegroundColor Cyan
gh @ghArgs
if ($LASTEXITCODE -ne 0) { throw "gh release create failed." }

Write-Host "[release] DONE. v$Version is live." -ForegroundColor Green
