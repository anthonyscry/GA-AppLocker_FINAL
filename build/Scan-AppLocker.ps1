#Requires -Version 5.1
<#
.SYNOPSIS
    Scan computers and create AppLocker policy.
.DESCRIPTION
    Simple wrapper script that uses the GA-AppLocker module.

.PARAMETER ComputerName
    Computer(s) to scan. Default: local computer.
.PARAMETER OutputPath
    Where to save results. Default: C:\GA-AppLocker\Scans
.PARAMETER PolicyMode
    Audit or Enforce. Default: Audit
.PARAMETER IncludeEvents
    Include AppLocker events in scan.
.PARAMETER ApplyPolicy
    Apply policy to local GPO after creation.
.PARAMETER MergePolicy
    Merge with existing policy instead of replace.
.PARAMETER FromAD
    Get computers from Active Directory.
.PARAMETER ADSearchBase
    AD OU to search (when using -FromAD).
.PARAMETER ADOperatingSystem
    Filter AD computers by OS (when using -FromAD).

.EXAMPLE
    .\Scan-AppLocker.ps1
    # Scan local computer, create Audit policy

.EXAMPLE
    .\Scan-AppLocker.ps1 -ComputerName "PC1","PC2"
    # Scan multiple computers

.EXAMPLE
    .\Scan-AppLocker.ps1 -FromAD -ApplyPolicy -MergePolicy
    # Scan all AD computers, apply merged policy

.EXAMPLE
    .\Scan-AppLocker.ps1 -PolicyMode Enforce -ApplyPolicy
    # Create and apply Enforce policy
#>

[CmdletBinding(DefaultParameterSetName = "Direct")]
param(
    [Parameter(ParameterSetName = "Direct", ValueFromPipeline)]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = "AD")]
    [switch]$FromAD,

    [Parameter(ParameterSetName = "AD")]
    [string]$ADSearchBase,

    [Parameter(ParameterSetName = "AD")]
    [string]$ADOperatingSystem,

    [string]$OutputPath = "C:\GA-AppLocker\Scans",

    [ValidateSet("Audit", "Enforce")]
    [string]$PolicyMode = "Audit",

    [switch]$IncludeEvents,
    [switch]$ApplyPolicy,
    [switch]$MergePolicy
)

# Import module
$modulePath = Join-Path $PSScriptRoot "Modules\GA-AppLocker.psm1"
if (-not (Test-Path $modulePath)) {
    Write-Error "Module not found: $modulePath"
    exit 1
}
Import-Module $modulePath -Force

# Get computers
if ($FromAD) {
    Write-Host "Getting computers from Active Directory..." -ForegroundColor Cyan
    $params = @{ MaxCount = 100 }
    if ($ADSearchBase) { $params["SearchBase"] = $ADSearchBase }
    if ($ADOperatingSystem) { $params["OperatingSystem"] = $ADOperatingSystem }
    $ComputerName = Get-ADComputerList @params
    Write-Host "Found $($ComputerName.Count) computers" -ForegroundColor Green
    Write-Host ""
}

if (-not $ComputerName) {
    $ComputerName = @($env:COMPUTERNAME)
}

# Run scan
$result = Invoke-AppLockerScan `
    -ComputerName $ComputerName `
    -OutputPath $OutputPath `
    -PolicyMode $PolicyMode `
    -IncludeEvents:$IncludeEvents `
    -ApplyPolicy:$ApplyPolicy `
    -MergePolicy:$MergePolicy

# Return result
return $result
