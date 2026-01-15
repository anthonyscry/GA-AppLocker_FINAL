# Build-Only.ps1
# Fast build script - compiles GA-AppLocker Dashboard as an executable
# No tests, no analysis - just pure build for quick iteration

param(
    [string]$OutputPath = ".\output",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

# Write build header
Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Dashboard - FAST BUILD" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

function Write-BuildStep {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor Cyan
}

function Write-BuildSuccess {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor Green
}

function Write-BuildError {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor Red
}

$startTime = Get-Date

# Step 1: Clean output directory
Write-BuildStep "Step 1: Cleaning output directory..."
if (Test-Path $OutputPath) {
    Remove-Item -Path "$OutputPath\*" -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-BuildSuccess "Output directory ready"

# Step 2: Check for PS2EXE module
Write-BuildStep "Step 2: Checking PS2EXE module..."

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "  Installing ps2exe module..." -ForegroundColor Yellow
    try {
        Install-Module -Name ps2exe -Force -Scope CurrentUser -ErrorAction Stop
        Write-BuildSuccess "PS2EXE installed"
    }
    catch {
        Write-BuildError "Failed to install PS2EXE: $($_.Exception.Message)"
        Write-Host "  Try running: Install-Module -Name ps2exe -Force" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-BuildSuccess "PS2EXE module found"
}

# Step 3: Build the executable
Write-BuildStep "Step 3: Building standalone GUI executable..."

# Use the WPF GUI script as input (modern GitHub-style interface)
$guiScriptPath = ".\build\GA-AppLocker-GUI-WPF.ps1"

# Fallback to the full GUI if WPF version not found
if (-not (Test-Path $guiScriptPath)) {
    $guiScriptPath = ".\build\GA-AppLocker-GUI-Full.ps1"
}

# Fallback to portable version
if (-not (Test-Path $guiScriptPath)) {
    $guiScriptPath = ".\GA-AppLocker-1.2.4\src\GUI\GA-AppLocker-Portable.ps1"
}

if (-not (Test-Path $guiScriptPath)) {
    Write-BuildError "No GUI script found!"
    Write-Host "  Looked for:" -ForegroundColor Yellow
    Write-Host "    - .\build\GA-AppLocker-GUI-WPF.ps1" -ForegroundColor Gray
    Write-Host "    - .\build\GA-AppLocker-GUI-Full.ps1" -ForegroundColor Gray
    Write-Host "    - .\GA-AppLocker-1.2.4\src\GUI\GA-AppLocker-Portable.ps1" -ForegroundColor Gray
    exit 1
}

Write-Host "  Using: $guiScriptPath" -ForegroundColor Gray

# Copy GUI script to output
$wrapperPath = "$OutputPath\GA-AppLocker-GUI.ps1"
Copy-Item -Path $guiScriptPath -Destination $wrapperPath -Force

# Compile with PS2EXE
try {
    Import-Module ps2exe -ErrorAction Stop

    $exePath = "$OutputPath\GA-AppLocker-Dashboard.exe"

    Write-Host "  Compiling to: $exePath" -ForegroundColor Gray

    $ps2exeParams = @{
        InputFile  = $wrapperPath
        OutputFile = $exePath
        Title      = "GA-AppLocker Dashboard"
        NoConsole  = $true
        NoOutput   = $true
    }

    # Run PS2EXE
    ps2exe @ps2exeParams -ErrorAction Stop

    if (Test-Path $exePath) {
        $fileSize = (Get-Item $exePath).Length / 1MB
        Write-BuildSuccess "Executable built: $exePath ($([math]::Round($fileSize, 2)) MB)"
    }
    else {
        throw "PS2EXE completed but executable not found"
    }
}
catch {
    Write-BuildError "PS2EXE build failed: $($_.Exception.Message)"
    Write-Host "`n  Creating portable package instead..." -ForegroundColor Yellow

    # Create portable ZIP package as fallback
    $zipPath = "$OutputPath\GA-AppLocker-Dashboard-Portable.zip"

    # Create a simple launcher batch file
    $batchLauncher = @"
@echo off
echo Starting GA-AppLocker Dashboard...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0GA-AppLocker-GUI.ps1"
pause
"@
    $batchLauncher | Out-File "$OutputPath\Launch-GA-AppLocker.bat" -Encoding ASCII

    # Create the ZIP
    try {
        Compress-Archive -Path "$OutputPath\GA-AppLocker-GUI.ps1", "$OutputPath\Launch-GA-AppLocker.bat" -DestinationPath $zipPath -Force
        Write-BuildSuccess "Portable package created: $zipPath"
    }
    catch {
        Write-BuildError "Failed to create portable package: $($_.Exception.Message)"
    }
}

# Step 4: Create quick release folder
Write-BuildStep "Step 4: Creating release folder..."

$version = "1.2.4"
$releaseDir = "$OutputPath\release-$version"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

# Copy built files
if (Test-Path "$OutputPath\GA-AppLocker-Dashboard.exe") {
    Copy-Item -Path "$OutputPath\GA-AppLocker-Dashboard.exe" -Destination $releaseDir
}
if (Test-Path "$OutputPath\GA-AppLocker-GUI.ps1") {
    Copy-Item -Path "$OutputPath\GA-AppLocker-GUI.ps1" -Destination $releaseDir
}
if (Test-Path "$OutputPath\Launch-GA-AppLocker.bat") {
    Copy-Item -Path "$OutputPath\Launch-GA-AppLocker.bat" -Destination $releaseDir
}

# Copy README if exists
if (Test-Path ".\README.md") {
    Copy-Item -Path ".\README.md" -Destination $releaseDir
}

Write-BuildSuccess "Release folder created: $releaseDir"

# Build summary
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n====================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host "`nOutput location: $OutputPath" -ForegroundColor Cyan
Write-Host "Release folder:  $releaseDir" -ForegroundColor Cyan
Write-Host "Build time:      $([math]::Round($duration.TotalSeconds, 1)) seconds" -ForegroundColor Cyan
Write-Host "`n"

# List output contents
Write-Host "Build artifacts:" -ForegroundColor Yellow
Get-ChildItem -Path $OutputPath -File | ForEach-Object {
    $size = if ($_.Length -gt 1MB) { "$([math]::Round($_.Length/1MB, 2)) MB" } else { "$([math]::Round($_.Length/1KB, 1)) KB" }
    Write-Host "  - $($_.Name) ($size)" -ForegroundColor Gray
}
