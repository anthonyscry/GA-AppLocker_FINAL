<#
.SYNOPSIS
    Deployment state management ViewModel

.DESCRIPTION
    Manages AppLocker policy deployment state including GPO configuration,
    enforcement mode, and deployment history for the Deployment panel.

.NOTES
    Module Name: DeploymentViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/PolicyManager

.EXAMPLE
    Import-Module .\DeploymentViewModel.ps1

    # Initialize and configure deployment
    Initialize-DeploymentState
    Set-EnforcementMode -Mode "Audit"
    Update-GPOName -GPOName "AppLocker-Policy-v1"

.EXAMPLE
    # Get current deployment status
    $status = Get-DeploymentStatus
    Write-Host "Enforcement Mode: $($status.EnforcementMode)"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:DeploymentState = [hashtable]::Synchronized(@{
    GPOName = ""
    GPOGuid = ""
    EnforcementMode = "NotConfigured"  # NotConfigured, Audit, Enforce
    TargetOU = ""
    TargetComputers = @()
    IsDeployed = $false
    LastDeploymentDate = $null
    LastModifiedDate = $null
    DeploymentUser = ""
    PolicyVersion = "1.0"
    BackupPath = ""
    RollbackAvailable = $false
})

$script:PolicyData = [hashtable]::Synchronized(@{
    XmlContent = ""
    RuleCount = 0
    Collections = @{
        Exe = @{ Enabled = $false; RuleCount = 0 }
        Msi = @{ Enabled = $false; RuleCount = 0 }
        Script = @{ Enabled = $false; RuleCount = 0 }
        Dll = @{ Enabled = $false; RuleCount = 0 }
        Appx = @{ Enabled = $false; RuleCount = 0 }
    }
    ValidationStatus = "NotValidated"  # NotValidated, Valid, Invalid
    ValidationErrors = @()
})

$script:DeploymentHistory = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

# ============================================================
# PUBLIC FUNCTIONS - INITIALIZATION & STATUS
# ============================================================

function Initialize-DeploymentState {
    <#
    .SYNOPSIS
        Initializes the deployment state

    .DESCRIPTION
        Resets deployment state and loads current policy configuration if available

    .EXAMPLE
        Initialize-DeploymentState
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing deployment state..."

        # Reset deployment state
        $script:DeploymentState.GPOName = ""
        $script:DeploymentState.GPOGuid = ""
        $script:DeploymentState.EnforcementMode = "NotConfigured"
        $script:DeploymentState.TargetOU = ""
        $script:DeploymentState.TargetComputers = @()
        $script:DeploymentState.IsDeployed = $false
        $script:DeploymentState.LastDeploymentDate = $null
        $script:DeploymentState.LastModifiedDate = $null
        $script:DeploymentState.DeploymentUser = ""
        $script:DeploymentState.PolicyVersion = "1.0"
        $script:DeploymentState.BackupPath = ""
        $script:DeploymentState.RollbackAvailable = $false

        # Reset policy data
        $script:PolicyData.XmlContent = ""
        $script:PolicyData.RuleCount = 0
        $script:PolicyData.ValidationStatus = "NotValidated"
        $script:PolicyData.ValidationErrors = @()

        # Clear history
        $script:DeploymentHistory.Clear()

        # Try to load current effective policy
        Load-CurrentPolicyState

        Write-Verbose "Deployment state initialized"
        return @{ success = $true; message = "Deployment state initialized" }
    }
    catch {
        Write-Warning "Failed to initialize deployment state: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DeploymentStatus {
    <#
    .SYNOPSIS
        Gets current deployment status

    .DESCRIPTION
        Returns the current deployment state including GPO, enforcement mode, and deployment info

    .OUTPUTS
        Hashtable containing deployment status

    .EXAMPLE
        $status = Get-DeploymentStatus
        Write-Host "GPO: $($status.GPOName), Mode: $($status.EnforcementMode)"
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            GPOName = $script:DeploymentState.GPOName
            GPOGuid = $script:DeploymentState.GPOGuid
            EnforcementMode = $script:DeploymentState.EnforcementMode
            TargetOU = $script:DeploymentState.TargetOU
            TargetComputers = $script:DeploymentState.TargetComputers
            IsDeployed = $script:DeploymentState.IsDeployed
            LastDeploymentDate = $script:DeploymentState.LastDeploymentDate
            LastModifiedDate = $script:DeploymentState.LastModifiedDate
            DeploymentUser = $script:DeploymentState.DeploymentUser
            PolicyVersion = $script:DeploymentState.PolicyVersion
            BackupPath = $script:DeploymentState.BackupPath
            RollbackAvailable = $script:DeploymentState.RollbackAvailable
            PolicyRuleCount = $script:PolicyData.RuleCount
            ValidationStatus = $script:PolicyData.ValidationStatus
        }
    }
    catch {
        Write-Warning "Failed to get deployment status: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DeploymentSummary {
    <#
    .SYNOPSIS
        Gets a concise deployment summary

    .OUTPUTS
        Hashtable with summary information

    .EXAMPLE
        $summary = Get-DeploymentSummary
    #>
    [CmdletBinding()]
    param()

    try {
        $status = if ($script:DeploymentState.IsDeployed) {
            "Deployed"
        } elseif ($script:PolicyData.RuleCount -gt 0) {
            "Ready"
        } else {
            "Not Configured"
        }

        return @{
            Status = $status
            Mode = $script:DeploymentState.EnforcementMode
            GPO = $script:DeploymentState.GPOName
            Rules = $script:PolicyData.RuleCount
            LastDeployed = if ($script:DeploymentState.LastDeploymentDate) {
                $script:DeploymentState.LastDeploymentDate.ToString("yyyy-MM-dd HH:mm")
            } else {
                "Never"
            }
        }
    }
    catch {
        Write-Warning "Failed to get deployment summary: $($_.Exception.Message)"
        return @{ Status = "Error"; Message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - CONFIGURATION
# ============================================================

function Set-EnforcementMode {
    <#
    .SYNOPSIS
        Sets the policy enforcement mode

    .PARAMETER Mode
        Enforcement mode: NotConfigured, Audit, or Enforce

    .EXAMPLE
        Set-EnforcementMode -Mode "Audit"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("NotConfigured", "Audit", "Enforce")]
        [string]$Mode
    )

    try {
        Write-Verbose "Setting enforcement mode to: $Mode..."

        $previousMode = $script:DeploymentState.EnforcementMode
        $script:DeploymentState.EnforcementMode = $Mode
        $script:DeploymentState.LastModifiedDate = Get-Date

        # Log to history
        Add-DeploymentHistoryEntry -Action "SetEnforcementMode" -Details "Changed from $previousMode to $Mode"

        Write-Verbose "Enforcement mode set to: $Mode"
        return @{
            success = $true
            message = "Enforcement mode set to $Mode"
            previousMode = $previousMode
            newMode = $Mode
        }
    }
    catch {
        Write-Warning "Failed to set enforcement mode: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-GPOName {
    <#
    .SYNOPSIS
        Updates the GPO name for deployment

    .PARAMETER GPOName
        Name of the Group Policy Object

    .PARAMETER GPOGuid
        Optional GUID of the GPO

    .EXAMPLE
        Update-GPOName -GPOName "AppLocker-Production-Policy"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$GPOName,

        [Parameter()]
        [string]$GPOGuid
    )

    try {
        Write-Verbose "Updating GPO name to: $GPOName..."

        $script:DeploymentState.GPOName = $GPOName
        if ($GPOGuid) {
            $script:DeploymentState.GPOGuid = $GPOGuid
        }
        $script:DeploymentState.LastModifiedDate = Get-Date

        # Log to history
        Add-DeploymentHistoryEntry -Action "UpdateGPO" -Details "GPO name set to: $GPOName"

        Write-Verbose "GPO name updated"
        return @{ success = $true; message = "GPO name updated"; gpoName = $GPOName }
    }
    catch {
        Write-Warning "Failed to update GPO name: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Set-TargetOU {
    <#
    .SYNOPSIS
        Sets the target OU for GPO deployment

    .PARAMETER TargetOU
        Distinguished name of the target OU

    .EXAMPLE
        Set-TargetOU -TargetOU "OU=Workstations,DC=contoso,DC=com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetOU
    )

    try {
        Write-Verbose "Setting target OU to: $TargetOU..."

        $script:DeploymentState.TargetOU = $TargetOU
        $script:DeploymentState.LastModifiedDate = Get-Date

        # Log to history
        Add-DeploymentHistoryEntry -Action "SetTargetOU" -Details "Target OU: $TargetOU"

        Write-Verbose "Target OU set"
        return @{ success = $true; message = "Target OU set"; targetOU = $TargetOU }
    }
    catch {
        Write-Warning "Failed to set target OU: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Set-TargetComputers {
    <#
    .SYNOPSIS
        Sets the list of target computers for deployment

    .PARAMETER ComputerNames
        Array of computer names

    .EXAMPLE
        Set-TargetComputers -ComputerNames @("PC01", "PC02", "PC03")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames
    )

    try {
        Write-Verbose "Setting target computers ($($ComputerNames.Count) computers)..."

        $script:DeploymentState.TargetComputers = $ComputerNames
        $script:DeploymentState.LastModifiedDate = Get-Date

        # Log to history
        Add-DeploymentHistoryEntry -Action "SetTargetComputers" -Details "$($ComputerNames.Count) target computers"

        Write-Verbose "Target computers set"
        return @{ success = $true; message = "Target computers set"; count = $ComputerNames.Count }
    }
    catch {
        Write-Warning "Failed to set target computers: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - POLICY MANAGEMENT
# ============================================================

function Get-PolicyXml {
    <#
    .SYNOPSIS
        Gets the current policy XML

    .OUTPUTS
        XML string of the current policy

    .EXAMPLE
        $xml = Get-PolicyXml
    #>
    [CmdletBinding()]
    param()

    try {
        return $script:PolicyData.XmlContent
    }
    catch {
        Write-Warning "Failed to get policy XML: $($_.Exception.Message)"
        return ""
    }
}

function Set-PolicyXml {
    <#
    .SYNOPSIS
        Sets the policy XML content

    .PARAMETER XmlContent
        AppLocker policy XML content

    .PARAMETER ValidateXml
        Whether to validate the XML (default: $true)

    .EXAMPLE
        Set-PolicyXml -XmlContent $xmlString
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$XmlContent,

        [Parameter()]
        [bool]$ValidateXml = $true
    )

    try {
        Write-Verbose "Setting policy XML..."

        if ($ValidateXml) {
            $validationResult = Test-PolicyXml -XmlContent $XmlContent
            if (-not $validationResult.success) {
                throw "Policy XML validation failed: $($validationResult.message)"
            }
        }

        $script:PolicyData.XmlContent = $XmlContent
        $script:PolicyData.ValidationStatus = if ($ValidateXml) { "Valid" } else { "NotValidated" }
        $script:DeploymentState.LastModifiedDate = Get-Date

        # Parse rule count from XML
        Update-PolicyMetadata

        Write-Verbose "Policy XML set successfully"
        return @{ success = $true; message = "Policy XML set" }
    }
    catch {
        Write-Warning "Failed to set policy XML: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-DeploymentStatus {
    <#
    .SYNOPSIS
        Updates deployment status after a deployment operation

    .PARAMETER IsDeployed
        Whether the policy is currently deployed

    .PARAMETER DeploymentUser
        User who performed the deployment

    .EXAMPLE
        Update-DeploymentStatus -IsDeployed $true -DeploymentUser $env:USERNAME
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$IsDeployed,

        [Parameter()]
        [string]$DeploymentUser
    )

    try {
        Write-Verbose "Updating deployment status (IsDeployed: $IsDeployed)..."

        $script:DeploymentState.IsDeployed = $IsDeployed

        if ($IsDeployed) {
            $script:DeploymentState.LastDeploymentDate = Get-Date
            $script:DeploymentState.DeploymentUser = if ($DeploymentUser) { $DeploymentUser } else { $env:USERNAME }

            # Log to history
            Add-DeploymentHistoryEntry -Action "Deploy" -Details "Policy deployed to $($script:DeploymentState.GPOName)"
        }

        Write-Verbose "Deployment status updated"
        return @{ success = $true; message = "Deployment status updated" }
    }
    catch {
        Write-Warning "Failed to update deployment status: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-DeploymentHistory {
    <#
    .SYNOPSIS
        Gets the deployment history

    .PARAMETER MaxEntries
        Maximum number of history entries to return (default: all)

    .OUTPUTS
        Array of deployment history entries

    .EXAMPLE
        $history = Get-DeploymentHistory -MaxEntries 10
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MaxEntries = 0
    )

    try {
        $history = $script:DeploymentHistory.ToArray()

        if ($MaxEntries -gt 0 -and $history.Count -gt $MaxEntries) {
            $history = $history | Select-Object -Last $MaxEntries
        }

        return $history
    }
    catch {
        Write-Warning "Failed to get deployment history: $($_.Exception.Message)"
        return @()
    }
}

function Clear-DeploymentState {
    <#
    .SYNOPSIS
        Clears the deployment state

    .EXAMPLE
        Clear-DeploymentState
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing deployment state..."
        Initialize-DeploymentState
        return @{ success = $true; message = "Deployment state cleared" }
    }
    catch {
        Write-Warning "Failed to clear deployment state: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Load-CurrentPolicyState {
    [CmdletBinding()]
    param()

    try {
        # Attempt to load effective AppLocker policy
        # This would call BusinessLogic/PolicyManager
        # For now, just placeholder logic
        Write-Verbose "Loading current policy state..."
    }
    catch {
        Write-Verbose "No current policy loaded: $($_.Exception.Message)"
    }
}

function Test-PolicyXml {
    param([string]$XmlContent)

    try {
        # Validate XML structure
        $null = [xml]$XmlContent

        # Basic AppLocker policy validation
        if (-not $XmlContent.Contains("AppLockerPolicy")) {
            throw "Invalid AppLocker policy XML"
        }

        return @{ success = $true; message = "XML is valid" }
    }
    catch {
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-PolicyMetadata {
    [CmdletBinding()]
    param()

    try {
        if (-not $script:PolicyData.XmlContent) {
            return
        }

        [xml]$policyXml = $script:PolicyData.XmlContent

        # Count rules
        $totalRules = 0
        $ruleCollections = $policyXml.AppLockerPolicy.RuleCollection

        foreach ($collection in $ruleCollections) {
            $collectionType = $collection.Type
            $ruleCount = 0

            if ($collection.FilePublisherRule) { $ruleCount += $collection.FilePublisherRule.Count }
            if ($collection.FileHashRule) { $ruleCount += $collection.FileHashRule.Count }
            if ($collection.FilePathRule) { $ruleCount += $collection.FilePathRule.Count }

            $totalRules += $ruleCount

            if ($script:PolicyData.Collections.ContainsKey($collectionType)) {
                $script:PolicyData.Collections[$collectionType].Enabled = $true
                $script:PolicyData.Collections[$collectionType].RuleCount = $ruleCount
            }
        }

        $script:PolicyData.RuleCount = $totalRules
    }
    catch {
        Write-Verbose "Failed to update policy metadata: $($_.Exception.Message)"
    }
}

function Add-DeploymentHistoryEntry {
    param(
        [string]$Action,
        [string]$Details
    )

    try {
        $entry = [PSCustomObject]@{
            Timestamp = Get-Date
            Action = $Action
            Details = $Details
            User = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
        }

        [void]$script:DeploymentHistory.Add($entry)

        # Keep only last 100 entries
        if ($script:DeploymentHistory.Count -gt 100) {
            $script:DeploymentHistory.RemoveAt(0)
        }
    }
    catch {
        Write-Verbose "Failed to add history entry: $($_.Exception.Message)"
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-DeploymentState',
    'Get-DeploymentStatus',
    'Get-DeploymentSummary',
    'Set-EnforcementMode',
    'Update-GPOName',
    'Set-TargetOU',
    'Set-TargetComputers',
    'Get-PolicyXml',
    'Set-PolicyXml',
    'Update-DeploymentStatus',
    'Get-DeploymentHistory',
    'Clear-DeploymentState'
)
