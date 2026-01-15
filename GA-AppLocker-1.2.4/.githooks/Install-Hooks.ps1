<#
.SYNOPSIS
    Installs Git hooks for GA-AppLocker development.

.DESCRIPTION
    Configures Git to use the project's .githooks directory and verifies
    required development tools are installed.

.EXAMPLE
    .\.githooks\Install-Hooks.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "`nGA-AppLocker Development Setup" -ForegroundColor Cyan
Write-Host "==============================`n" -ForegroundColor Cyan

# Find repo root
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    # Configure git hooks path
    Write-Host "1. Configuring Git hooks path..." -ForegroundColor Yellow
    git config core.hooksPath .githooks
    Write-Host "   [OK] Git hooks configured to use .githooks/" -ForegroundColor Green

    # Check for PSScriptAnalyzer
    Write-Host "`n2. Checking PSScriptAnalyzer..." -ForegroundColor Yellow
    $analyzer = Get-Module -ListAvailable PSScriptAnalyzer
    if ($analyzer) {
        Write-Host "   [OK] PSScriptAnalyzer v$($analyzer.Version) installed" -ForegroundColor Green
    } else {
        Write-Host "   [MISSING] PSScriptAnalyzer not found" -ForegroundColor Red
        Write-Host "   Install with: Install-Module PSScriptAnalyzer -Scope CurrentUser" -ForegroundColor DarkGray
    }

    # Check for Pester
    Write-Host "`n3. Checking Pester..." -ForegroundColor Yellow
    $pester = Get-Module -ListAvailable Pester | Where-Object Version -ge '5.0.0'
    if ($pester) {
        Write-Host "   [OK] Pester v$($pester.Version) installed" -ForegroundColor Green
    } else {
        Write-Host "   [MISSING] Pester 5.0+ not found" -ForegroundColor Red
        Write-Host "   Install with: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force" -ForegroundColor DarkGray
    }

    # Verify hooks are executable
    Write-Host "`n4. Checking hook files..." -ForegroundColor Yellow
    $hookFiles = @('pre-commit')
    foreach ($hook in $hookFiles) {
        $hookPath = Join-Path $PSScriptRoot $hook
        if (Test-Path $hookPath) {
            Write-Host "   [OK] $hook hook exists" -ForegroundColor Green
        } else {
            Write-Host "   [MISSING] $hook hook not found" -ForegroundColor Red
        }
    }

    # Summary
    Write-Host "`n==============================" -ForegroundColor Cyan
    Write-Host "Setup Complete!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "  1. Install any missing modules listed above" -ForegroundColor White
    Write-Host "  2. Run .\scripts\Invoke-LocalValidation.ps1 to verify setup" -ForegroundColor White
    Write-Host "  3. Pre-commit hooks will now run automatically on git commit" -ForegroundColor White

} finally {
    Pop-Location
}
