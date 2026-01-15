<#
.SYNOPSIS
    Sets up Git hooks for GA-AppLocker project
.DESCRIPTION
    Configures Git to use the .githooks directory for hooks,
    enabling pre-commit linting and validation.
.EXAMPLE
    .\Setup-GitHooks.ps1
#>

[CmdletBinding()]
param()

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$hooksDir = Join-Path $projectRoot ".githooks"

Write-Host "Setting up Git hooks..." -ForegroundColor Cyan
Write-Host "Project root: $projectRoot" -ForegroundColor Gray
Write-Host "Hooks directory: $hooksDir`n" -ForegroundColor Gray

# Check if .githooks directory exists
if (-not (Test-Path $hooksDir)) {
    Write-Host "[WARN] .githooks directory not found at $hooksDir" -ForegroundColor Yellow
    exit 1
}

# Check if we're in a git repository
$gitDir = Join-Path $projectRoot ".git"
if (-not (Test-Path $gitDir)) {
    Write-Host "[WARN] Not a Git repository" -ForegroundColor Yellow
    exit 1
}

# Configure Git to use our hooks directory
try {
    Push-Location $projectRoot
    git config core.hooksPath .githooks
    Pop-Location
    Write-Host "[OK] Git hooks path configured to .githooks" -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to configure Git hooks: $_" -ForegroundColor Red
    exit 1
}

# Make hooks executable (for Unix-like systems)
$hookFiles = Get-ChildItem -Path $hooksDir -File
foreach ($hook in $hookFiles) {
    Write-Host "[OK] Hook registered: $($hook.Name)" -ForegroundColor Green
}

Write-Host "`nGit hooks setup complete!" -ForegroundColor Green
Write-Host "The following hooks are now active:" -ForegroundColor Cyan
Write-Host "  - pre-commit: Runs PSScriptAnalyzer and XAML validation" -ForegroundColor Gray
