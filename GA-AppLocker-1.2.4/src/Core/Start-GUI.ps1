<#
.SYNOPSIS
    Launches the GA-AppLocker WPF GUI Application
.DESCRIPTION
    This is a launcher script that starts the graphical user interface
    for the GA-AppLocker toolkit.
.EXAMPLE
    .\Start-GUI.ps1
.NOTES
    Requires: PowerShell 5.1+, Windows Presentation Foundation
#>

#Requires -Version 5.1

$srcRoot = Split-Path -Parent $PSScriptRoot
$guiPath = Join-Path $srcRoot "GUI\GA-AppLocker-Portable.ps1"

if (Test-Path $guiPath) {
    & $guiPath
} else {
    Write-Error "GUI script not found. Expected: $guiPath"
    exit 1
}
