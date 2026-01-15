# GA-AppLocker.psm1
# Main controller module for GA-AppLocker Dashboard
# Loads all modules and provides unified interface

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath 'modules'

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

foreach ($module in $modules) {
    $moduleFile = Join-Path $modulePath $module
    if (Test-Path $moduleFile) {
        Import-Module $moduleFile -Force -ErrorAction SilentlyContinue
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

    Import-Module (Join-Path $modulePath 'Module1-Dashboard.psm1') -ErrorAction SilentlyContinue
    return Module1\Get-DashboardSummary @args
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

    Import-Module (Join-Path $modulePath 'Module2-RemoteScan.psm1') -ErrorAction SilentlyContinue
    return Module2\Get-AllADComputers @args
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

    Import-Module (Join-Path $modulePath 'Module2-RemoteScan.psm1') -ErrorAction SilentlyContinue
    return Module2\Get-ExecutableArtifacts @args
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

    Import-Module (Join-Path $modulePath 'Module3-RuleGenerator.psm1') -ErrorAction SilentlyContinue
    return Module3\New-RulesFromArtifacts @args
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

    Import-Module (Join-Path $modulePath 'Module3-RuleGenerator.psm1') -ErrorAction SilentlyContinue
    return Module3\Export-RulesToXml @args
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

    Import-Module (Join-Path $modulePath 'Module4-PolicyLab.psm1') -ErrorAction SilentlyContinue
    return Module4\New-AppLockerGPO @args
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

    Import-Module (Join-Path $modulePath 'Module4-PolicyLab.psm1') -ErrorAction SilentlyContinue
    return Module4\Add-GPOLink @args
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

    Import-Module (Join-Path $modulePath 'Module4-PolicyLab.psm1') -ErrorAction SilentlyContinue
    return Module4\Get-OUsWithComputerCounts @args
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

    Import-Module (Join-Path $modulePath 'Module5-EventMonitor.psm1') -ErrorAction SilentlyContinue
    return Module5\Get-AppLockerEvents @args
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

    Import-Module (Join-Path $modulePath 'Module6-ADManager.psm1') -ErrorAction SilentlyContinue
    return Module6\Get-AllADUsers @args
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

    Import-Module (Join-Path $modulePath 'Module6-ADManager.psm1') -ErrorAction SilentlyContinue
    return Module6\New-AppLockerGroups @args
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

    Import-Module (Join-Path $modulePath 'Module6-ADManager.psm1') -ErrorAction SilentlyContinue
    return Module6\Add-UserToAppLockerGroup @args
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

    Import-Module (Join-Path $modulePath 'Module7-Compliance.psm1') -ErrorAction SilentlyContinue
    return Module7\Get-ComplianceSummary @args
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

    Import-Module (Join-Path $modulePath 'Module7-Compliance.psm1') -ErrorAction SilentlyContinue
    return Module7\New-ComplianceReport @args
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
