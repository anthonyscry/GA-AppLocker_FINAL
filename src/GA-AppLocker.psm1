# GA-AppLocker.psm1
# Main controller module for GA-AppLocker Dashboard
# Loads all modules and provides unified interface
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library first
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$libPath = Join-Path $scriptPath 'lib'
$modulePath = Join-Path $scriptPath 'modules'
$commonPath = Join-Path $libPath 'Common.psm1'
$configPath = Join-Path $scriptPath 'Config.psm1'

# Import Common and Config modules
if (Test-Path $commonPath) {
    Import-Module $commonPath -Force -ErrorAction Stop
}
if (Test-Path $configPath) {
    Import-Module $configPath -Force -ErrorAction Stop
}

# Load all modules
$modules = @(
    'Module1-Dashboard.psm1',
    'Module2-RemoteScan.psm1',
    'Module3-RuleGenerator.psm1',
    'Module4-PolicyLab.psm1',
    'Module5-EventMonitor.psm1',
    'Module6-ADManager.psm1',
    'Module7-Compliance.psm1'
)

$loadedModules = @()
$failedModules = @()

foreach ($module in $modules) {
    $moduleFile = Join-Path $modulePath $module
    if (Test-Path $moduleFile) {
        try {
            Import-Module $moduleFile -Force -ErrorAction Stop
            $loadedModules += $module
        }
        catch {
            $failedModules += @{
                module = $module
                error = $_.Exception.Message
            }
        }
    }
    else {
        $failedModules += @{
            module = $module
            error = "File not found: $moduleFile"
        }
    }
}

# Log module loading status
if ($failedModules.Count -gt 0) {
    Write-Warning "Some GA-AppLocker modules failed to load:"
    foreach ($failure in $failedModules) {
        Write-Warning "  - $($failure.module): $($failure.error)"
    }
}

<#
.SYNOPSIS
    Get Dashboard Summary
.DESCRIPTION
    Returns complete dashboard statistics for p2s frontend
#>
function Get-DashboardSummary {
    [CmdletBinding()]
    param()

    $moduleFile = Join-Path $modulePath 'Module1-Dashboard.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module1-Dashboard.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-DashboardSummary @args
}

<#
.SYNOPSIS
    Get All Computers
.DESCRIPTION
    Returns all computers from AD
#>
function Get-AllComputers {
    [CmdletBinding()]
    param()

    $moduleFile = Join-Path $modulePath 'Module2-RemoteScan.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module2-RemoteScan.psm1"; data = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-AllADComputers @args
}

<#
.SYNOPSIS
    Scan Local Computer
.DESCRIPTION
    Scans local computer for executable artifacts
#>
function Scan-LocalComputer {
    [CmdletBinding()]
    param(
        [string]$TargetPath = 'C:\Program Files'
    )

    $moduleFile = Join-Path $modulePath 'Module2-RemoteScan.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module2-RemoteScan.psm1"; data = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-ExecutableArtifacts @args
}

<#
.SYNOPSIS
    Generate Rules
.DESCRIPTION
    Generates AppLocker rules from artifacts
#>
function Generate-Rules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Artifacts,
        [ValidateSet('Publisher', 'Path', 'Hash')]
        [string]$RuleType = 'Publisher'
    )

    $moduleFile = Join-Path $modulePath 'Module3-RuleGenerator.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module3-RuleGenerator.psm1"; rules = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return New-RulesFromArtifacts @args
}

<#
.SYNOPSIS
    Export Policy
.DESCRIPTION
    Exports rules to AppLocker XML policy file
#>
function Export-Policy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Rules,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [ValidateSet('AuditOnly', 'Enabled')]
        [string]$EnforcementMode = 'AuditOnly'
    )

    $moduleFile = Join-Path $modulePath 'Module3-RuleGenerator.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module3-RuleGenerator.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Export-RulesToXml @args
}

<#
.SYNOPSIS
    Create GPO
.DESCRIPTION
    Creates a new GPO for AppLocker
#>
function Create-GPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName
    )

    $moduleFile = Join-Path $modulePath 'Module4-PolicyLab.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module4-PolicyLab.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return New-AppLockerGPO @args
}

<#
.SYNOPSIS
    Link GPO to OU
.DESCRIPTION
    Links a GPO to an organizational unit
#>
function Link-GPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GpoName,
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )

    $moduleFile = Join-Path $modulePath 'Module4-PolicyLab.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module4-PolicyLab.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Add-GPOLink @args
}

<#
.SYNOPSIS
    Get OUs
.DESCRIPTION
    Returns all OUs with computer counts
#>
function Get-AllOUs {
    [CmdletBinding()]
    param()

    $moduleFile = Join-Path $modulePath 'Module4-PolicyLab.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module4-PolicyLab.psm1"; data = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-OUsWithComputerCounts @args
}

<#
.SYNOPSIS
    Get Events
.DESCRIPTION
    Returns AppLocker events
#>
function Get-Events {
    [CmdletBinding()]
    param(
        [int]$MaxEvents = 100,
        [string]$FilterType = 'All'
    )

    $moduleFile = Join-Path $modulePath 'Module5-EventMonitor.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module5-EventMonitor.psm1"; data = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-AppLockerEvents @args
}

<#
.SYNOPSIS
    Get AD Users
.DESCRIPTION
    Returns all AD users
#>
function Get-Users {
    [CmdletBinding()]
    param()

    $moduleFile = Join-Path $modulePath 'Module6-ADManager.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module6-ADManager.psm1"; data = @() }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-AllADUsers @args
}

<#
.SYNOPSIS
    Create AppLocker Groups
.DESCRIPTION
    Creates standard AppLocker security groups
#>
function Create-AppLockerGroups {
    [CmdletBinding()]
    param(
        [string]$TargetOU
    )

    $moduleFile = Join-Path $modulePath 'Module6-ADManager.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module6-ADManager.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return New-AppLockerGroups @args
}

<#
.SYNOPSIS
    Add User to Group
.DESCRIPTION
    Adds a user to an AppLocker group
#>
function Add-UserToGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    $moduleFile = Join-Path $modulePath 'Module6-ADManager.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module6-ADManager.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Add-UserToAppLockerGroup @args
}

<#
.SYNOPSIS
    Get Compliance Summary
.DESCRIPTION
    Returns compliance status summary
#>
function Get-Compliance {
    [CmdletBinding()]
    param()

    $moduleFile = Join-Path $modulePath 'Module7-Compliance.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module7-Compliance.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return Get-ComplianceSummary @args
}

<#
.SYNOPSIS
    Generate Compliance Report
.DESCRIPTION
    Creates HTML compliance report
#>
function New-Report {
    [CmdletBinding()]
    param(
        [string]$OutputPath = 'C:\AppLocker\Evidence\Reports\ComplianceReport.html'
    )

    $moduleFile = Join-Path $modulePath 'Module7-Compliance.psm1'
    if (-not (Test-Path $moduleFile)) {
        return @{ success = $false; error = "Module not found: Module7-Compliance.psm1" }
    }
    Import-Module $moduleFile -ErrorAction Stop
    return New-ComplianceReport @args
}

# Export all functions
Export-ModuleMember -Function @(
    'Get-DashboardSummary',
    'Get-AllComputers',
    'Scan-LocalComputer',
    'Generate-Rules',
    'Export-Policy',
    'Create-GPO',
    'Link-GPO',
    'Get-AllOUs',
    'Get-Events',
    'Get-Users',
    'Create-AppLockerGroups',
    'Add-UserToGroup',
    'Get-Compliance',
    'New-Report'
)
