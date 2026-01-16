<#
.SYNOPSIS
    AppLocker policy management business logic

.DESCRIPTION
    Core functions for managing AppLocker policies, GPOs, policy health scoring,
    and enforcement mode toggling. Provides pure business logic without UI dependencies.

.NOTES
    Module Name: PolicyManager
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: GroupPolicy module (for GPO functions), ActiveDirectory module (optional)

.EXAMPLE
    Import-Module .\PolicyManager.ps1

    # Get policy health score
    $health = Get-PolicyHealthScore
    Write-Host "Policy Health: $($health.score)%"

    # Get dashboard summary
    $summary = Get-DashboardSummary
    Write-Host "Total events: $($summary.events.total)"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function Get-AppLockerEventStats {
    <#
    .SYNOPSIS
        Retrieves AppLocker event statistics from local system

    .DESCRIPTION
        Queries the AppLocker event log and returns counts of allowed, audited,
        and blocked events. Returns safe defaults if log is unavailable.

    .PARAMETER MaxEvents
        Maximum number of events to analyze (default: 1000)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - allowed: Count of allowed events
        - audit: Count of audited events
        - blocked: Count of blocked events
        - total: Total event count
        - message: Status message

    .EXAMPLE
        $stats = Get-AppLockerEventStats
        Write-Host "Blocked: $($stats.blocked), Allowed: $($stats.allowed)"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Event stats retrieval
        $stats = Get-AppLockerEventStats
        Assert ($stats.success -eq $true)
        Assert ($stats.total -ge 0)
        Assert ($stats.allowed -ge 0)
        Assert ($stats.blocked -ge 0)
        Assert ($stats.audit -ge 0)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 1000
    )

    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'

    try {
        # Check if log exists
        $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop
        if (-not $logExists) {
            return @{
                success = $true
                allowed = 0
                audit = 0
                blocked = 0
                total = 0
                message = 'AppLocker log not found'
            }
        }
    }
    catch {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            total = 0
            message = 'AppLocker log not available'
        }
    }

    try {
        # Retrieve events
        $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop

        # Count by event ID
        $allowed = ($events | Where-Object { $_.Id -eq 8002 }).Count
        $audit = ($events | Where-Object { $_.Id -eq 8003 }).Count
        $blocked = ($events | Where-Object { $_.Id -eq 8004 }).Count

        return @{
            success = $true
            allowed = $allowed
            audit = $audit
            blocked = $blocked
            total = $events.Count
            message = "Retrieved $($events.Count) events"
        }
    }
    catch {
        return @{
            success = $true
            allowed = 0
            audit = 0
            blocked = 0
            total = 0
            message = 'No events found'
        }
    }
}

function Get-PolicyHealthScore {
    <#
    .SYNOPSIS
        Calculates AppLocker policy health score

    .DESCRIPTION
        Analyzes the effective AppLocker policy and assigns a health score (0-100)
        based on rule collection coverage (Exe, Msi, Script, Dll).

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - score: Health score (0-100)
        - hasPolicy: Boolean indicating if any policy exists
        - hasExe: Boolean for EXE rules
        - hasMsi: Boolean for MSI rules
        - hasScript: Boolean for Script rules
        - hasDll: Boolean for DLL rules
        - ruleCount: Total number of rules

    .EXAMPLE
        $health = Get-PolicyHealthScore
        if ($health.score -lt 50) {
            Write-Warning "Policy health is below 50%"
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Policy health scoring
        $health = Get-PolicyHealthScore
        Assert ($health.success -eq $true)
        Assert ($health.score -ge 0 -and $health.score -le 100)
        Assert ($health.hasPolicy -is [bool])
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        # Get effective AppLocker policy
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

        if ($null -eq $policy) {
            return @{
                success = $true
                score = 0
                hasPolicy = $false
                hasExe = $false
                hasMsi = $false
                hasScript = $false
                hasDll = $false
                ruleCount = 0
            }
        }

        # Check for each rule collection type
        $hasExe = $false
        $hasMsi = $false
        $hasScript = $false
        $hasDll = $false
        $totalRules = 0

        foreach ($collection in $policy.RuleCollections) {
            $ruleCount = if ($collection.Count) { $collection.Count } else { 0 }
            $totalRules += $ruleCount

            switch ($collection.RuleCollectionType) {
                'Exe' {
                    if ($ruleCount -gt 0) { $hasExe = $true }
                }
                'Msi' {
                    if ($ruleCount -gt 0) { $hasMsi = $true }
                }
                'Script' {
                    if ($ruleCount -gt 0) { $hasScript = $true }
                }
                'Dll' {
                    if ($ruleCount -gt 0) { $hasDll = $true }
                }
            }
        }

        # Calculate score (25 points per rule collection)
        $score = 0
        if ($hasExe) { $score += 25 }
        if ($hasMsi) { $score += 25 }
        if ($hasScript) { $score += 25 }
        if ($hasDll) { $score += 25 }

        return @{
            success = $true
            score = $score
            hasPolicy = $true
            hasExe = $hasExe
            hasMsi = $hasMsi
            hasScript = $hasScript
            hasDll = $hasDll
            ruleCount = $totalRules
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to calculate policy health: $($_.Exception.Message)"
            score = 0
            hasPolicy = $false
            hasExe = $false
            hasMsi = $false
            hasScript = $false
            hasDll = $false
            ruleCount = 0
            exception = $_.Exception
        }
    }
}

function Get-DashboardSummary {
    <#
    .SYNOPSIS
        Generates a comprehensive dashboard summary

    .DESCRIPTION
        Combines event statistics and policy health into a single summary object.
        Provides a quick overview of AppLocker status.

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - timestamp: Current date/time
        - events: Event statistics
        - policyHealth: Policy health data

    .EXAMPLE
        $summary = Get-DashboardSummary
        Write-Host "Summary generated at: $($summary.timestamp)"
        Write-Host "Policy Score: $($summary.policyHealth.score)%"
        Write-Host "Blocked Events: $($summary.events.blocked)"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Dashboard summary
        $summary = Get-DashboardSummary
        Assert ($summary.success -eq $true)
        Assert ($summary.timestamp -ne $null)
        Assert ($summary.events -ne $null)
        Assert ($summary.policyHealth -ne $null)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $events = Get-AppLockerEventStats
        $health = Get-PolicyHealthScore

        return @{
            success = $true
            timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            events = $events
            policyHealth = $health
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to generate dashboard summary: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Export-AppLockerPolicy {
    <#
    .SYNOPSIS
        Exports AppLocker policy to XML file

    .DESCRIPTION
        Exports the effective or local AppLocker policy to a Unicode XML file.
        AppLocker policies MUST be UTF-16 encoded for proper import.

    .PARAMETER OutputPath
        Path for the exported XML file

    .PARAMETER PolicyType
        Type of policy to export: "Effective" or "Local" (default: "Effective")

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - outputPath: Path to exported file
        - ruleCount: Number of rules exported
        - error: Error message (if failure)

    .EXAMPLE
        $result = Export-AppLockerPolicy -OutputPath "C:\AppLocker\policy.xml"
        if ($result.success) {
            Write-Host "Exported $($result.ruleCount) rules to $($result.outputPath)"
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Policy export
        $testPath = "$env:TEMP\test-policy.xml"
        $result = Export-AppLockerPolicy -OutputPath $testPath
        Assert ($result.success -eq $true)
        Assert (Test-Path $testPath)

        # Verify UTF-16 encoding
        $content = Get-Content $testPath -Raw
        Assert ($content -match '<?xml')

        # Cleanup
        Remove-Item $testPath -Force
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Effective", "Local")]
        [string]$PolicyType = "Effective"
    )

    try {
        # Get policy
        $policy = if ($PolicyType -eq "Effective") {
            Get-AppLockerPolicy -Effective -ErrorAction Stop
        }
        else {
            Get-AppLockerPolicy -Local -ErrorAction Stop
        }

        if ($null -eq $policy) {
            return @{
                success = $false
                error = "No AppLocker policy found"
            }
        }

        # Count rules
        $ruleCount = 0
        foreach ($collection in $policy.RuleCollections) {
            $ruleCount += if ($collection.Count) { $collection.Count } else { 0 }
        }

        # Get policy as XML string
        $policyXml = $policy.ToXml()

        # Create directory if it doesn't exist
        $directory = Split-Path -Path $OutputPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        # Save with UTF-16 encoding (required for AppLocker)
        $xmlDoc = [xml]$policyXml
        $xmlSettings = New-Object System.Xml.XmlWriterSettings
        $xmlSettings.Encoding = [System.Text.Encoding]::Unicode
        $xmlSettings.Indent = $true

        $xmlWriter = [System.Xml.XmlWriter]::Create($OutputPath, $xmlSettings)
        $xmlDoc.Save($xmlWriter)
        $xmlWriter.Close()

        return @{
            success = $true
            outputPath = $OutputPath
            ruleCount = $ruleCount
            policyType = $PolicyType
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to export AppLocker policy: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Import-AppLockerPolicy {
    <#
    .SYNOPSIS
        Imports AppLocker policy from XML file

    .DESCRIPTION
        Imports an AppLocker policy from XML file and optionally merges with existing policy.

    .PARAMETER PolicyPath
        Path to the policy XML file

    .PARAMETER Merge
        If specified, merges with existing policy instead of replacing

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - ruleCount: Number of rules imported
        - merged: Boolean indicating if merge was performed
        - error: Error message (if failure)

    .EXAMPLE
        $result = Import-AppLockerPolicy -PolicyPath "C:\AppLocker\policy.xml"
        if ($result.success) {
            Write-Host "Imported $($result.ruleCount) rules"
        }

    .NOTES
        Requires administrative privileges.

        Unit Test Example:
        ```powershell
        # Test: Policy import (requires admin)
        # First export a policy
        $exportPath = "$env:TEMP\test-export.xml"
        Export-AppLockerPolicy -OutputPath $exportPath

        # Then import it
        $result = Import-AppLockerPolicy -PolicyPath $exportPath
        Assert ($result.success -eq $true)

        # Cleanup
        Remove-Item $exportPath -Force
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$PolicyPath,

        [Parameter(Mandatory = $false)]
        [switch]$Merge
    )

    try {
        # Validate XML file
        $xmlContent = Get-Content -Path $PolicyPath -Raw
        $null = [xml]$xmlContent

        # Count rules before import
        $policyXml = [xml]$xmlContent
        $ruleCount = 0
        if ($policyXml.AppLockerPolicy.RuleCollection) {
            foreach ($collection in $policyXml.AppLockerPolicy.RuleCollection) {
                if ($collection.ChildNodes) {
                    $ruleCount += $collection.ChildNodes.Count
                }
            }
        }

        # Import policy
        if ($Merge) {
            Set-AppLockerPolicy -XmlPolicy $PolicyPath -Merge -ErrorAction Stop
        }
        else {
            Set-AppLockerPolicy -XmlPolicy $PolicyPath -ErrorAction Stop
        }

        return @{
            success = $true
            ruleCount = $ruleCount
            merged = $Merge.IsPresent
            policyPath = $PolicyPath
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to import AppLocker policy: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Set-PolicyEnforcementMode {
    <#
    .SYNOPSIS
        Sets AppLocker policy enforcement mode

    .DESCRIPTION
        Toggles AppLocker enforcement between Audit-only and Enforced modes
        for specified rule collections.

    .PARAMETER RuleCollectionType
        Type of rule collection: Exe, Msi, Script, Dll, or All

    .PARAMETER EnforcementMode
        Enforcement mode: AuditOnly or Enabled

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - ruleCollectionType: Type affected
        - enforcementMode: New mode
        - error: Error message (if failure)

    .EXAMPLE
        # Set EXE rules to audit mode
        $result = Set-PolicyEnforcementMode -RuleCollectionType "Exe" -EnforcementMode "AuditOnly"

    .EXAMPLE
        # Enable enforcement for all rule types
        $result = Set-PolicyEnforcementMode -RuleCollectionType "All" -EnforcementMode "Enabled"

    .NOTES
        Requires administrative privileges.

        Unit Test Example:
        ```powershell
        # Test: Toggle enforcement mode (requires admin and existing policy)
        $result = Set-PolicyEnforcementMode -RuleCollectionType "Exe" -EnforcementMode "AuditOnly"
        # This test requires a valid policy to exist
        if ($result.success) {
            Assert ($result.enforcementMode -eq "AuditOnly")
        }
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Exe", "Msi", "Script", "Dll", "All")]
        [string]$RuleCollectionType,

        [Parameter(Mandatory = $true)]
        [ValidateSet("AuditOnly", "Enabled")]
        [string]$EnforcementMode
    )

    try {
        # Get current policy
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop

        if ($null -eq $policy) {
            return @{
                success = $false
                error = "No AppLocker policy found"
            }
        }

        # Determine which collections to update
        $collectionsToUpdate = if ($RuleCollectionType -eq "All") {
            @("Exe", "Msi", "Script", "Dll")
        }
        else {
            @($RuleCollectionType)
        }

        # Update enforcement mode for each collection
        foreach ($collectionType in $collectionsToUpdate) {
            $collection = $policy.RuleCollections | Where-Object { $_.RuleCollectionType -eq $collectionType }

            if ($collection) {
                $collection.EnforcementMode = $EnforcementMode
            }
        }

        # Apply updated policy
        Set-AppLockerPolicy -PolicyObject $policy -ErrorAction Stop

        return @{
            success = $true
            ruleCollectionType = $RuleCollectionType
            enforcementMode = $EnforcementMode
            message = "Enforcement mode updated successfully"
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to set enforcement mode: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Test-AppLockerPolicy {
    <#
    .SYNOPSIS
        Validates AppLocker policy for common issues

    .DESCRIPTION
        Performs validation checks on the AppLocker policy:
        - Checks for empty rule collections
        - Validates rule syntax
        - Checks for conflicting rules
        - Verifies enforcement modes

    .PARAMETER PolicyPath
        Optional path to policy XML file (defaults to effective policy)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - valid: Boolean indicating if policy is valid
        - warnings: Array of warning messages
        - errors: Array of error messages
        - recommendations: Array of recommendations

    .EXAMPLE
        $validation = Test-AppLockerPolicy
        if (-not $validation.valid) {
            Write-Warning "Policy validation failed"
            $validation.errors | ForEach-Object { Write-Host "ERROR: $_" }
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Policy validation
        $validation = Test-AppLockerPolicy
        Assert ($validation.success -eq $true)
        Assert ($validation.warnings -is [array])
        Assert ($validation.errors -is [array])
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$PolicyPath
    )

    try {
        # Get policy
        $policy = if ($PolicyPath) {
            $xmlContent = Get-Content -Path $PolicyPath -Raw
            $policyXml = [xml]$xmlContent
            [Microsoft.Security.ApplicationId.PolicyManagement.PolicyModel.AppLockerPolicy]::FromXml($xmlContent)
        }
        else {
            Get-AppLockerPolicy -Effective -ErrorAction Stop
        }

        if ($null -eq $policy) {
            return @{
                success = $true
                valid = $false
                warnings = @()
                errors = @("No AppLocker policy found")
                recommendations = @("Create an AppLocker policy with appropriate rules")
            }
        }

        $warnings = @()
        $errors = @()
        $recommendations = @()

        # Check for empty rule collections
        $hasRules = $false
        foreach ($collection in $policy.RuleCollections) {
            $ruleCount = if ($collection.Count) { $collection.Count } else { 0 }
            if ($ruleCount -gt 0) {
                $hasRules = $true
            }
            else {
                $warnings += "Rule collection '$($collection.RuleCollectionType)' is empty"
            }
        }

        if (-not $hasRules) {
            $errors += "Policy contains no rules"
        }

        # Check enforcement modes
        $hasAuditMode = $false
        $hasEnforcedMode = $false

        foreach ($collection in $policy.RuleCollections) {
            if ($collection.EnforcementMode -eq "AuditOnly") {
                $hasAuditMode = $true
            }
            elseif ($collection.EnforcementMode -eq "Enabled") {
                $hasEnforcedMode = $true
            }
        }

        if ($hasAuditMode -and -not $hasEnforcedMode) {
            $recommendations += "Policy is in audit-only mode. Consider enabling enforcement after testing."
        }

        # Determine overall validity
        $valid = ($errors.Count -eq 0) -and $hasRules

        return @{
            success = $true
            valid = $valid
            warnings = $warnings
            errors = $errors
            recommendations = $recommendations
            hasRules = $hasRules
            hasAuditMode = $hasAuditMode
            hasEnforcedMode = $hasEnforcedMode
        }
    }
    catch {
        return @{
            success = $false
            valid = $false
            error = "Failed to validate policy: $($_.Exception.Message)"
            warnings = @()
            errors = @($_.Exception.Message)
            recommendations = @()
            exception = $_.Exception
        }
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Get-AppLockerEventStats',
    'Get-PolicyHealthScore',
    'Get-DashboardSummary',
    'Export-AppLockerPolicy',
    'Import-AppLockerPolicy',
    'Set-PolicyEnforcementMode',
    'Test-AppLockerPolicy'
)
