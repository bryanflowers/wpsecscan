$ErrorActionPreference = 'Stop'
Uninstall-BinFile -Name 'wpsecscan'
Uninstall-BinFile -Name 'wpsecscan-gui'
Write-Host "WPSecScan uninstalled. ~/.wpsecscan/ left in place (delete manually if desired)."
