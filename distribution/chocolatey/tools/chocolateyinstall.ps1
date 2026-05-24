$ErrorActionPreference = 'Stop'

$packageName = 'wpsecscan'
$version = '2.0.0'
$cliUrl = "https://github.com/bryanflowers/wpsecscan/releases/download/v$version/wpsecscan.exe"
$guiUrl = "https://github.com/bryanflowers/wpsecscan/releases/download/v$version/wpsecscan-gui.exe"

$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Get-ChocolateyWebFile -PackageName $packageName -FileFullPath "$toolsDir\wpsecscan.exe" -Url $cliUrl
Get-ChocolateyWebFile -PackageName $packageName -FileFullPath "$toolsDir\wpsecscan-gui.exe" -Url $guiUrl

# Add to PATH automatically
Install-BinFile -Name 'wpsecscan' -Path "$toolsDir\wpsecscan.exe"
Install-BinFile -Name 'wpsecscan-gui' -Path "$toolsDir\wpsecscan-gui.exe"

Write-Host "WPSecScan installed. Try: wpsecscan --demo"
