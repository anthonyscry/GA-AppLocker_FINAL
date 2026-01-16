#Requires -Version 5.1
<#
.SYNOPSIS
    GA-AppLocker Main Module
.DESCRIPTION
    Main module that imports all GA-AppLocker sub-modules.
    Provides unified access to scanning, policy creation, and AD integration.

.EXAMPLE
    Import-Module .\Modules\GA-AppLocker.psm1
    $result = Invoke-ComprehensiveScan
    $policy = New-AppLockerPolicy -Publishers $result.Publishers
    Save-AppLockerPolicy -PolicyXml $policy -Path "C:\policy.xml"
#>

$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import sub-modules
$subModules = @(
    "GA-AppLocker.Common.psm1",
    "GA-AppLocker.Scan.psm1",
    "GA-AppLocker.Policy.psm1",
    "GA-AppLocker.AD.psm1"
)

foreach ($module in $subModules) {
    $modulePath = Join-Path $ModulePath $module
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    } else {
        Write-Warning "Sub-module not found: $modulePath"
    }
}

# ============================================================
# HIGH-LEVEL WORKFLOW FUNCTIONS
# ============================================================

function Invoke-AppLockerScan {
    <#
    .SYNOPSIS
        One-command scan and policy creation.
    .DESCRIPTION
        Scans computer(s), creates AppLocker policy, optionally applies it.

    .PARAMETER ComputerName
        Computer(s) to scan. Default: local computer.
    .PARAMETER OutputPath
        Where to save results. Default: C:\GA-AppLocker\Scans
    .PARAMETER PolicyMode
        Audit or Enforce. Default: Audit
    .PARAMETER IncludeEvents
        Include AppLocker events in scan.
    .PARAMETER ApplyPolicy
        Apply policy to local GPO.
    .PARAMETER MergePolicy
        Merge with existing policy instead of replace.

    .EXAMPLE
        Invoke-AppLockerScan
        # Scans local computer, creates Audit policy

    .EXAMPLE
        Invoke-AppLockerScan -ComputerName "PC1","PC2" -PolicyMode Enforce -ApplyPolicy
        # Scans multiple computers, creates Enforce policy, applies to GPO

    .EXAMPLE
        Get-ADComputerList | Invoke-AppLockerScan -MergePolicy
        # Scans all AD computers, merges results
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("CN", "Name")]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [string]$OutputPath = "C:\GA-AppLocker\Scans",

        [ValidateSet("Audit", "Enforce")]
        [string]$PolicyMode = "Audit",

        [switch]$IncludeEvents,
        [switch]$ApplyPolicy,
        [switch]$MergePolicy
    )

    begin {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $allPublishers = @{}
        $scannedComputers = @()

        # Ensure output path exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host " GA-AppLocker Scan" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Timestamp: $timestamp" -ForegroundColor White
        Write-Host "Output: $OutputPath" -ForegroundColor White
        Write-Host ""
    }

    process {
        foreach ($computer in $ComputerName) {
            Write-Host "--- Scanning: $computer ---" -ForegroundColor Yellow

            try {
                $result = Invoke-ComprehensiveScan -ComputerName $computer -OutputPath $OutputPath -IncludeEvents:$IncludeEvents

                # Merge publishers
                foreach ($key in $result.Publishers.Keys) {
                    if ($allPublishers.ContainsKey($key)) {
                        $allPublishers[$key].Count += $result.Publishers[$key].Count
                    } else {
                        $allPublishers[$key] = $result.Publishers[$key]
                    }
                }

                $scannedComputers += $computer
                Write-Host "  Done: $($result.Stats.Executables) executables, $($result.Stats.InstalledSoftware) software" -ForegroundColor Green

            } catch {
                Write-Host "  Failed: $_" -ForegroundColor Red
            }
            Write-Host ""
        }
    }

    end {
        # Create policy
        Write-Host "--- Creating AppLocker Policy ---" -ForegroundColor Yellow
        $policyXml = New-AppLockerPolicy -Publishers $allPublishers -PolicyMode $PolicyMode

        $policyFileName = "AppLocker-Policy-${PolicyMode}-${timestamp}.xml"
        $policyPath = Join-Path $OutputPath $policyFileName
        Save-AppLockerPolicy -PolicyXml $policyXml -Path $policyPath

        Write-Host "Policy saved: $policyPath" -ForegroundColor Green

        # Apply if requested
        if ($ApplyPolicy) {
            Write-Host ""
            Write-Host "--- Applying to Local GPO ---" -ForegroundColor Yellow
            try {
                Import-AppLockerPolicy -PolicyPath $policyPath -Merge:$MergePolicy
                Write-Host "Policy applied successfully!" -ForegroundColor Green
            } catch {
                Write-Host "Failed to apply: $_" -ForegroundColor Red
                Write-Host "Run as Administrator to apply policies." -ForegroundColor Yellow
            }
        }

        # Summary
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host " SCAN COMPLETE" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Computers scanned: $($scannedComputers.Count)" -ForegroundColor White
        Write-Host "Publishers found: $($allPublishers.Count)" -ForegroundColor White
        Write-Host "Policy: $policyPath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To import manually:" -ForegroundColor Cyan
        Write-Host "  Set-AppLockerPolicy -XmlPolicy `"$policyPath`" -Merge" -ForegroundColor Gray
        Write-Host ""

        return @{
            Success          = $true
            PolicyPath       = $policyPath
            ComputersScanned = $scannedComputers
            PublishersFound  = $allPublishers.Count
        }
    }
}

# ============================================================
# EXPORTS
# ============================================================

# Re-export all functions from sub-modules
Export-ModuleMember -Function @(
    # From Common
    'Get-Timestamp',
    'Get-ScanFolderPath',
    'Find-AaronLockerRoot',
    'Write-Status',
    'Test-RemoteAccess',
    'Export-ToCsv',
    'Save-XmlPolicy',

    # From Scan
    'Get-InstalledSoftware',
    'Get-Executables',
    'Get-AppLockerEvents',
    'Invoke-ComprehensiveScan',

    # From Policy
    'New-AppLockerPolicy',
    'Merge-AppLockerPolicy',
    'Save-AppLockerPolicy',
    'Import-AppLockerPolicy',

    # From AD
    'Test-ADModule',
    'Get-ADComputerList',
    'Get-ADComputerInfo',

    # High-level
    'Invoke-AppLockerScan'
)
