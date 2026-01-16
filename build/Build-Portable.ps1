# Build-Portable.ps1
# Creates a portable package (no PS2EXE compilation issues)

param(
    [string]$OutputPath = ".\output"
)

$ErrorActionPreference = "Stop"

Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Portable Build" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

# Step 1: Clean and create output directory
Write-Host "[Step 1] Creating portable package..." -ForegroundColor Cyan
if (Test-Path $OutputPath) {
    Remove-Item -Path "$OutputPath\*" -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Step 2: Copy GUI script to output
Write-Host "[Step 2] Copying WPF GUI script..." -ForegroundColor Cyan
Copy-Item -Path ".\GA-AppLocker-GUI-WPF.ps1" -Destination "$OutputPath\GA-AppLocker-Dashboard.ps1" -Force

# Step 3: Create batch launcher
Write-Host "[Step 3] Creating batch launcher..." -ForegroundColor Cyan
$launcher = @"
@echo off
REM GA-AppLocker Dashboard Launcher
title GA-AppLocker Dashboard
PowerShell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0GA-AppLocker-Dashboard.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo An error occurred. Press any key to exit...
    pause >nul
)
"@
$launcher | Out-File -FilePath "$OutputPath\GA-AppLocker-Dashboard.bat" -Encoding ASCII

# Step 4: Create portable ZIP package
Write-Host "[Step 4] Creating portable ZIP package..." -ForegroundColor Cyan
$version = "1.0.0"
$portableDir = "$OutputPath\GA-AppLocker-Portable"
New-Item -ItemType Directory -Path $portableDir -Force | Out-Null

# Copy files to portable directory
Copy-Item -Path "$OutputPath\GA-AppLocker-Dashboard.ps1" -Destination $portableDir -Force
Copy-Item -Path "$OutputPath\GA-AppLocker-Dashboard.bat" -Destination $portableDir -Force

# Copy source modules if they exist
if (Test-Path "..\src") {
    Write-Host "[Step 5] Including source modules..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path "$portableDir\modules" -Force | Out-Null
    Copy-Item -Path "..\src\*" -Destination "$portableDir\modules" -Recurse -Force
}

# Copy AaronLocker scripts (REQUIRED for AaronLocker Tools page)
if (Test-Path "..\AaronLocker-main") {
    Write-Host "[Step 6] Including AaronLocker scripts..." -ForegroundColor Cyan
    Copy-Item -Path "..\AaronLocker-main" -Destination "$portableDir\AaronLocker-main" -Recurse -Force
    Write-Host "         AaronLocker tools will be available at: AaronLocker-main\AaronLocker\" -ForegroundColor Gray
} else {
    Write-Host "[WARNING] AaronLocker-main folder not found - AaronLocker Tools page will not work!" -ForegroundColor Yellow
}

# Copy sample files if they exist
if (Test-Path "..\samples") {
    Write-Host "[Step 7] Including sample artifacts..." -ForegroundColor Cyan
    Copy-Item -Path "..\samples\*" -Destination "$portableDir" -Recurse -Force
}

# Create README
$readme = @"
# GA-AppLocker Dashboard v$version - Portable Edition

## Installation

No installation required! Simply extract all files to a folder of your choice.

## Running the Application

Double-click **GA-AppLocker-Dashboard.bat** to launch the application.

Or run from PowerShell:
```powershell
.\GA-AppLocker-Dashboard.ps1
```

## Features

- Dashboard Summary - View AppLocker policy health and event statistics
- AD Discovery - Find computers in Active Directory
- Artifact Collection - Scan computers for executable files
- Rule Generator - Create AppLocker rules from scanned artifacts
- Deployment Lab - Deploy policies via GPO
- Event Monitor - View AppLocker audit events
- Compliance Reports - Generate compliance reports
- WinRM Setup - Configure WinRM via GPO (1-click setup)
- AaronLocker Tools - Full GUI for AaronLocker scripts (scan, create policies, export)

## AaronLocker Integration

The AaronLocker-main folder is included with this package. Access it from the sidebar menu:
- Scan Directories for writable paths
- Create AppLocker/WDAC policies
- Export policies to CSV/Excel
- Configure local AppLocker settings
- Edit customization input files

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- .NET Framework 4.5+ (usually pre-installed)
- Administrator privileges recommended

## Workgroup Mode

If your computer is not joined to a domain:
- AD/GPO features will be automatically disabled
- Localhost scanning is available for testing
- WinRM GPO creation will be disabled

## Sample Data

Sample artifact files are included in the `samples` folder for testing the Rule Generator.

## Troubleshooting

If the application doesn't start:
1. Right-click GA-AppLocker-Dashboard.bat and select "Run as Administrator"
2. Run PowerShell as Administrator and execute: `Set-ExecutionPolicy Bypass -Scope Process`
3. Then run: `.\GA-AppLocker-Dashboard.ps1`

## Documentation

Full documentation available at: https://github.com/yourusername/GA-AppLocker

---

Built on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

$readme | Out-File -FilePath "$portableDir\README.txt" -Encoding UTF8

# Create ZIP
$zipPath = "$OutputPath\GA-AppLocker-Portable-v$version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$portableDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host "`n====================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host "`nOutput location: $OutputPath" -ForegroundColor White
Write-Host "Portable folder: $portableDir" -ForegroundColor White
Write-Host "ZIP package: $zipPath" -ForegroundColor White
Write-Host "`nTo run: Double-click GA-AppLocker-Dashboard.bat`n" -ForegroundColor Yellow
