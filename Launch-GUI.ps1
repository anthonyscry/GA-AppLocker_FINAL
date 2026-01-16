<#
.SYNOPSIS
    GA-AppLocker Dashboard Launcher
.DESCRIPTION
    Smart launcher that uses the stable GUI version
.NOTES
    The refactored v2.0 GUI needs fixes - using stable v1.3 for now
#>

param(
    [switch]$UseRefactored,
    [switch]$Verbose
)

Write-Host "GA-AppLocker Dashboard Launcher" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

if ($UseRefactored) {
    Write-Host "WARNING: Launching refactored v2.0 GUI (experimental)" -ForegroundColor Yellow
    Write-Host "Path: src\GUI\Main\GA-AppLocker-GUI.ps1" -ForegroundColor Gray
    Write-Host ""

    & "$PSScriptRoot\src\GUI\Main\GA-AppLocker-GUI.ps1"
} else {
    Write-Host "Launching stable GUI (v1.3 - monolithic)" -ForegroundColor Green
    Write-Host "Path: build\GA-AppLocker-GUI-WPF.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Note: Use -UseRefactored to try the new modular version" -ForegroundColor DarkGray
    Write-Host ""

    & "$PSScriptRoot\build\GA-AppLocker-GUI-WPF.ps1"
}
