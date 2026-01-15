#Requires -Version 5.1

<#
.SYNOPSIS
    GA-AppLocker PowerShell Module
.DESCRIPTION
    A simplified AppLocker deployment toolkit for Windows security administrators.
    Automates creating and managing Windows AppLocker policies through:
    - Remote computer inventory scanning
    - AppLocker audit event collection
    - Policy generation (Build Guide and Simplified modes)
    - Policy merge and validation
.NOTES
    Author: Tony Tran
    Information Systems Security Officer
    GA-ASI
#>

# Get module root path
$Script:ModuleRoot = $PSScriptRoot
$Script:SrcRoot = Join-Path $Script:ModuleRoot 'src'

# Import the Common module for shared functions
Import-Module (Join-Path $Script:SrcRoot 'Utilities\Common.psm1') -Force

# Import the ErrorHandling module for standardized error handling
Import-Module (Join-Path $Script:SrcRoot 'Utilities\ErrorHandling.psm1') -Force

#region Wrapper Functions

<#
.SYNOPSIS
    Starts the AppLocker workflow in interactive or parameter mode.
.DESCRIPTION
    Main entry point for GA-AppLocker functionality. Supports both interactive
    menu mode and direct parameter mode for scripting.
.PARAMETER Mode
    Operation mode: Scan, Events, Generate, Merge, Validate, Compare, Full
.PARAMETER ComputerList
    Path to file containing target computer names
.PARAMETER ScanPath
    Path to scan data for policy generation
.PARAMETER Simplified
    Use simplified policy generation mode
.EXAMPLE
    Start-AppLockerWorkflow
    # Launches interactive menu
.EXAMPLE
    Start-AppLockerWorkflow -Mode Scan -ComputerList .\computers.txt
    # Runs remote scan on specified computers
#>
function Start-AppLockerWorkflow {
    [CmdletBinding()]
    param(
        [ValidateSet('Scan', 'Events', 'Generate', 'Merge', 'Validate', 'Compare', 'Full', 'Software', 'AD', 'Diagnostics')]
        [string]$Mode,

        [string]$ComputerList,
        [string]$ScanPath,
        [string]$EventPath,
        [string]$PolicyPath,
        [string]$OutputPath,
        [switch]$Simplified,
        [ValidateSet('Workstation', 'Server', 'DomainController')]
        [string]$TargetType,
        [string]$DomainName,
        [ValidateRange(1, 4)]
        [int]$Phase = 1,
        [int]$DaysBack = 14,
        [switch]$IncludeAllowedEvents,
        [switch]$IncludeDenyRules,
        [switch]$IncludeHashRules
    )

    $scriptPath = Join-Path $Script:SrcRoot 'Core\Start-AppLockerWorkflow.ps1'
    & $scriptPath @PSBoundParameters
}

<#
.SYNOPSIS
    Performs remote scanning of computers for software inventory.
.PARAMETER ComputerListPath
    Path to file containing target computer names
.PARAMETER OutputPath
    Directory to store scan results
.PARAMETER Credential
    Credentials for remote connections
#>
function Invoke-RemoteScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerListPath,

        [string]$OutputPath = '.\Scans',
        [PSCredential]$Credential,
        [int]$ThrottleLimit = 10,
        [switch]$ScanUserProfiles,
        [switch]$CollectPublishers
    )

    $scriptPath = Join-Path $Script:SrcRoot 'Core\Invoke-RemoteScan.ps1'
    & $scriptPath @PSBoundParameters
}

<#
.SYNOPSIS
    Collects AppLocker audit events from remote computers.
.PARAMETER ComputerListPath
    Path to file containing target computer names
.PARAMETER DaysBack
    Number of days of events to collect (0 = all)
#>
function Invoke-RemoteEventCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerListPath,

        [string]$OutputPath = '.\Events',
        [PSCredential]$Credential,
        [int]$DaysBack = 14,
        [int]$MaxEvents = 5000,
        [switch]$BlockedOnly,
        [switch]$IncludeAllowedEvents,
        [int]$ThrottleLimit = 10
    )

    $scriptPath = Join-Path $Script:SrcRoot 'Core\Invoke-RemoteEventCollection.ps1'
    & $scriptPath @PSBoundParameters
}

<#
.SYNOPSIS
    Generates AppLocker policies from scan data.
.PARAMETER Simplified
    Use simplified mode (single target user)
.PARAMETER TargetType
    Target type for Build Guide mode
.PARAMETER Phase
    Deployment phase (1-4) for Build Guide mode
#>
function New-AppLockerPolicyFromGuide {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Simplified,
        [string]$TargetUser = 'Everyone',
        [string]$ScanPath,
        [string]$EventPath,
        [string]$SoftwareListPath,
        [string]$OutputPath = '.\Outputs',
        [ValidateSet('AuditOnly', 'Enabled')]
        [string]$EnforcementMode = 'AuditOnly',
        [switch]$IncludeDenyRules,
        [switch]$IncludeHashRules,

        # Build Guide mode parameters
        [ValidateSet('Workstation', 'Server', 'DomainController')]
        [string]$TargetType = 'Workstation',
        [string]$DomainName,
        [ValidateRange(1, 4)]
        [int]$Phase = 1,
        [string]$AdminsGroup,
        [string]$StandardUsersGroup,
        [string]$ServiceAccountsGroup,
        [string]$InstallersGroup,
        [switch]$IncludeVendorPublishers,
        [string[]]$VendorPublishers = @(),
        [switch]$SkipDenyRules
    )

    $scriptPath = Join-Path $Script:SrcRoot 'Core\New-AppLockerPolicyFromGuide.ps1'
    & $scriptPath @PSBoundParameters
}

<#
.SYNOPSIS
    Merges multiple AppLocker policies into one.
.PARAMETER PolicyPaths
    Array of paths to policy files to merge
.PARAMETER OutputPath
    Path for the merged policy output
#>
function Merge-AppLockerPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$PolicyPaths,

        [string]$OutputPath = '.\Outputs',
        [switch]$RemoveDuplicates,
        [switch]$PreserveEnforcementMode
    )

    $scriptPath = Join-Path $Script:SrcRoot 'Core\Merge-AppLockerPolicies.ps1'
    & $scriptPath @PSBoundParameters
}

#endregion

#region Aliases

Set-Alias -Name 'gaapp' -Value 'Start-AppLockerWorkflow' -Scope Global

#endregion

# Export functions - include all from nested modules
Export-ModuleMember -Function @(
    # Wrapper functions
    'Start-AppLockerWorkflow',
    'Invoke-RemoteScan',
    'Invoke-RemoteEventCollection',
    'New-AppLockerPolicyFromGuide',
    'Merge-AppLockerPolicies',

    # Common module functions (re-exported)
    'Test-AppLockerPolicy',
    'Test-ScanData',
    'Compare-AppLockerPolicies',
    'Resolve-AccountToSid',
    'Resolve-AccountsToSids',
    'Get-StandardPrincipalSids',
    'Clear-SidCache',
    'Get-SidCacheStats',
    'Get-AppLockerConfig',
    'Start-Logging',
    'Write-Log',
    'Stop-Logging',
    'Get-ComputerList',
    'Confirm-Directory',

    # ErrorHandling module functions (re-exported)
    'Invoke-SafeOperation',
    'Write-ErrorMessage',
    'Test-ValidPath',
    'Test-ValidXml',
    'Test-ValidAppLockerPolicy',
    'Test-ValidComputerList',
    'Test-RequiredKeys',
    'Write-SectionHeader',
    'Write-StepProgress',
    'Write-SuccessMessage',
    'Write-ResultSummary',
    'Initialize-GAAppLockerScript',
    'Test-CredentialValidity'
) -Alias @('gaapp')

Write-Verbose "GA-AppLocker module loaded from $Script:ModuleRoot"
