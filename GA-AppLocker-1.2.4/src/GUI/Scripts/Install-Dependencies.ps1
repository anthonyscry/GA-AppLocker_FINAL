<#
.SYNOPSIS
    Installs development dependencies for GA-AppLocker GUI
.DESCRIPTION
    Installs PSScriptAnalyzer and Pester modules required for linting and testing.
.EXAMPLE
    .\Install-Dependencies.ps1
.EXAMPLE
    .\Install-Dependencies.ps1 -Scope AllUsers
#>

[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser'
)

$modules = @(
    @{ Name = 'PSScriptAnalyzer'; MinVersion = '1.21.0' }
    @{ Name = 'Pester'; MinVersion = '5.0.0' }
)

Write-Host "Installing development dependencies..." -ForegroundColor Cyan
Write-Host "Scope: $Scope`n" -ForegroundColor Gray

foreach ($module in $modules) {
    $installed = Get-Module -ListAvailable $module.Name |
        Where-Object { $_.Version -ge [version]$module.MinVersion } |
        Select-Object -First 1

    if ($installed) {
        Write-Host "[OK] $($module.Name) v$($installed.Version) already installed" -ForegroundColor Green
    } else {
        Write-Host "[INSTALL] $($module.Name) (min v$($module.MinVersion))..." -ForegroundColor Yellow
        try {
            Install-Module -Name $module.Name -MinimumVersion $module.MinVersion -Scope $Scope -Force -AllowClobber
            Write-Host "[OK] $($module.Name) installed successfully" -ForegroundColor Green
        } catch {
            Write-Host "[FAIL] Failed to install $($module.Name): $_" -ForegroundColor Red
        }
    }
}

Write-Host "`nVerifying installations..." -ForegroundColor Cyan

foreach ($module in $modules) {
    $installed = Get-Module -ListAvailable $module.Name | Select-Object -First 1
    if ($installed) {
        Write-Host "  $($module.Name): v$($installed.Version)" -ForegroundColor Green
    } else {
        Write-Host "  $($module.Name): NOT FOUND" -ForegroundColor Red
    }
}

Write-Host "`nDone!" -ForegroundColor Green
