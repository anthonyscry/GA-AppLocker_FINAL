# Build-EXE.ps1
# Build script to compile GA-AppLocker Dashboard as an executable

param(
    [string]$OutputPath = ".\output",
    [string]$Configuration = "Release",
    [switch]$SkipTests,
    [switch]$SkipAnalysis
)

$ErrorActionPreference = "Stop"

# Write build header
Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Dashboard Build" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

# Function to write colored messages
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

# Step 1: Clean output directory
Write-BuildStep "Step 1: Cleaning output directory..."
if (Test-Path $OutputPath) {
    Remove-Item -Path "$OutputPath\*" -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Write-BuildSuccess "Output directory cleaned"

# Step 2: Run PSScriptAnalyzer
if (-not $SkipAnalysis) {
    Write-BuildStep "Step 2: Running PSScriptAnalyzer..."

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "  Installing PSScriptAnalyzer..." -ForegroundColor Yellow
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
    }

    Import-Module PSScriptAnalyzer

    $analysisResults = Invoke-ScriptAnalyzer -Path ".\src" -Settings ".\PSScriptAnalyzerSettings.psd1" -Recurse

    if ($analysisResults) {
        Write-BuildError "PSScriptAnalyzer found $($analysisResults.Count) issue(s):"
        $analysisResults | Format-Table -AutoSize

        $errors = $analysisResults | Where-Object { $_.Severity -eq 'Error' }
        if ($errors) {
            throw "Build failed: PSScriptAnalyzer found $($errors.Count) error(s)"
        }
    } else {
        Write-BuildSuccess "No PSScriptAnalyzer issues found"
    }
} else {
    Write-Host "  [Skipped] PSScriptAnalyzer analysis" -ForegroundColor Yellow
}

# Step 3: Run Pester tests
if (-not $SkipTests) {
    Write-BuildStep "Step 3: Running Pester tests..."

    if (-not (Get-Module -ListAvailable -Name Pester)) {
        Write-Host "  Installing Pester..." -ForegroundColor Yellow
        Install-Module -Name Pester -Force -MinimumVersion 5.0 -Scope CurrentUser -SkipPublisherCheck
    }

    Import-Module Pester -MinimumVersion 5.0

    $config = New-PesterConfiguration
    $config.Run.Path = ".\tests"
    $config.Run.Exit = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = "$OutputPath\PesterResults.xml"

    try {
        $result = Invoke-Pester -Configuration $config
        Write-BuildSuccess "Pester tests passed: $($result.PassedCount) passed, $($result.FailedCount) failed"
    }
    catch {
        throw "Build failed: Pester tests failed"
    }
} else {
    Write-Host "  [Skipped] Pester tests" -ForegroundColor Yellow
}

# Step 4: Build the executable
Write-BuildStep "Step 4: Building executable..."

# Check for PS2EXE module
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "  Installing ps2exe..." -ForegroundColor Yellow
    Install-Module -Name ps2exe -Force -Scope CurrentUser
}

# Create a wrapper script for the EXE
$wrapperScript = @"
# GA-AppLocker Dashboard - Auto-generated wrapper
# This script serves as the entry point for the compiled executable

`$scriptPath = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$modulePath = Join-Path `$scriptPath "modules"
`$libPath = Join-Path `$scriptPath "lib"

# Import modules
Import-Module (Join-Path `$libPath "Common.psm1") -Force
Import-Module (Join-Path `$modulePath "Module1-Dashboard.psm1") -Force
Import-Module (Join-Path `$modulePath "Module2-RemoteScan.psm1") -Force
Import-Module (Join-Path `$modulePath "Module3-RuleGenerator.psm1") -Force
Import-Module (Join-Path `$modulePath "Module4-PolicyLab.psm1") -Force
Import-Module (Join-Path `$modulePath "Module5-EventMonitor.psm1") -Force
Import-Module (Join-Path `$modulePath "Module6-ADManager.psm1") -Force
Import-Module (Join-Path `$modulePath "Module7-Compliance.psm1") -Force

# Show welcome message
Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Dashboard v1.0" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan
Write-Host "Modules loaded successfully!" -ForegroundColor Green
Write-Host "`nAvailable commands:" -ForegroundColor Yellow
Write-Host "  - Get-DashboardSummary" -ForegroundColor White
Write-Host "  - Get-AllComputers" -ForegroundColor White
Write-Host "  - Scan-LocalComputer" -ForegroundColor White
Write-Host "  - Generate-Rules" -ForegroundColor White
Write-Host "  - Export-Policy" -ForegroundColor White
Write-Host "  - Create-GPO" -ForegroundColor White
Write-Host "  - Link-GPO" -ForegroundColor White
Write-Host "  - Get-Events" -ForegroundColor White
Write-Host "  - Get-Compliance" -ForegroundColor White
Write-Host "`nType 'help <command>' for more information.`n" -ForegroundColor Gray

# Keep shell open
`$null = Read-Host "Press Enter to exit"
"@

$wrapperPath = "$OutputPath\GA-AppLocker-Wrapper.ps1"
$wrapperScript | Out-File -FilePath $wrapperPath -Encoding UTF8

# Prepare source files for packaging
$packageDir = "$OutputPath\package"
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
Copy-Item -Path ".\src\*" -Destination $packageDir -Recurse -Force

# Compile with PS2EXE
try {
    Import-Module ps2exe

    $exePath = "$OutputPath\GA-AppLocker-Dashboard.exe"

    Write-Host "  Compiling to: $exePath" -ForegroundColor Gray

    # PS2EXE parameters
    $ps2exeParams = @{
        InputFile  = $wrapperPath
        OutputFile = $exePath
        IconFile   = ".\build\icon.ico"
        Title      = "GA-AppLocker Dashboard"
        ConfigFile = ".\build\ps2exe.config.json"
    }

    # Try to compile with PS2EXE
    & win-ps2exe @ps2exeParams -ErrorAction Stop

    if (Test-Path $exePath) {
        $fileSize = (Get-Item $exePath).Length / 1MB
        Write-BuildSuccess "Executable built: $exePath ($([math]::Round($fileSize, 2)) MB)"
    }
    else {
        throw "PS2EXE compilation failed - executable not found"
    }
}
catch {
    Write-BuildError "PS2EXE build failed: $($_.Exception.Message)"
    Write-Host "`n  Falling back to portable script package..." -ForegroundColor Yellow

    # Create a portable launcher instead
    $launcherScript = @"
# GA-AppLocker Dashboard Launcher
`$moduleRoot = Split-Path -Parent `$MyInvocation.MyCommand.Path

# Add modules to path
`$env:PSModulePath = "`$moduleRoot`;" + `$env:PSModulePath

# Import main module
Import-Module "`$moduleRoot\GA-AppLocker.psm1" -Force

# Launch dashboard
Write-Host "`n====================================" -ForegroundColor Cyan
Write-Host "  GA-AppLocker Dashboard v1.0" -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

# Show menu
while (`$true) {
    Write-Host "`nSelect an option:" -ForegroundColor Yellow
    Write-Host "  1. Dashboard Summary" -ForegroundColor White
    Write-Host "  2. Scan Computers" -ForegroundColor White
    Write-Host "  3. Generate Rules" -ForegroundColor White
    Write-Host "  4. Deploy Policy" -ForegroundColor White
    Write-Host "  5. View Events" -ForegroundColor White
    Write-Host "  6. Compliance Report" -ForegroundColor White
    Write-Host "  Q. Quit" -ForegroundColor White

    `$choice = Read-Host "`nChoice"

    switch (`$choice) {
        '1' { Get-DashboardSummary | ConvertTo-Json -Depth 10 }
        '2' { Get-AllComputers | ConvertTo-Json -Depth 10 }
        '3' { Write-Host "Use Scan-LocalComputer and Generate-Rules cmdlets" }
        '4' { Write-Host "Use Create-GPO and Link-GPO cmdlets" }
        '5' { Get-Events | ConvertTo-Json -Depth 10 }
        '6' { New-Report }
        'Q' { break }
    }
}
"@

    $portablePath = "$OutputPath\GA-AppLocker-Dashboard.ps1"
    $launcherScript | Out-File -FilePath $portablePath -Encoding UTF8

    # Create portable package
    $zipPath = "$OutputPath\GA-AppLocker-Dashboard-Portable.zip"
    Compress-Archive -Path ".\src\*", $portablePath -DestinationPath $zipPath -Force

    Write-BuildSuccess "Portable package created: $zipPath"
}

# Step 5: Create release package
Write-BuildStep "Step 5: Creating release package..."

$version = "1.0.0"
$releaseDir = "$OutputPath\release-$version"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

# Copy built files
if (Test-Path "$OutputPath\GA-AppLocker-Dashboard.exe") {
    Copy-Item -Path "$OutputPath\GA-AppLocker-Dashboard.exe" -Destination $releaseDir
}
Copy-Item -Path ".\src\*" -Destination "$releaseDir\modules" -Recurse -Force
Copy-Item -Path ".\README.md" -Destination $releaseDir
Copy-Item -Path ".\PSScriptAnalyzerSettings.psd1" -Destination $releaseDir

# Create release notes
$releaseNotes = @"
# GA-AppLocker Dashboard v$version

## Installation
1. Copy all files to C:\Program Files\GA-AppLocker\
2. Run GA-AppLocker-Dashboard.exe as Administrator
3. Import modules: Import-Module "C:\Program Files\GA-AppLocker\GA-AppLocker.psm1"

## Quick Start
```powershell
# Get dashboard summary
Get-DashboardSummary

# Scan local computer
Scan-LocalComputer

# Generate rules
Generate-Rules -Artifacts `$artifacts -RuleType Publisher
```

## Modules Included
- Module 1: Dashboard
- Module 2: Remote Scan
- Module 3: Rule Generator
- Module 4: Policy Lab
- Module 5: Event Monitor
- Module 6: AD Manager
- Module 7: Compliance

## Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Domain Administrator privileges
- Active Directory PowerShell module
- Group Policy PowerShell module

## Documentation
See README.md for full documentation.

---
Built on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

$releaseNotes | Out-File -FilePath "$releaseDir\ReleaseNotes.txt" -Encoding UTF8

Write-BuildSuccess "Release package created: $releaseDir"

# Build complete
Write-BuildSuccess "`n===================================="
Write-BuildSuccess "  BUILD COMPLETED SUCCESSFULLY"
Write-BuildSuccess "===================================="
Write-BuildSuccess "`nOutput location: $OutputPath"
Write-BuildSuccess "Release package: $releaseDir"
Write-Host "`n"