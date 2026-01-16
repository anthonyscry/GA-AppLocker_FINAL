<#
.SYNOPSIS
    Rules collection management ViewModel

.DESCRIPTION
    Manages the generated AppLocker rules collection, providing CRUD operations,
    filtering, sorting, and statistics for the Rules panel in the UI.
    This ViewModel maintains the rules state and interacts with BusinessLogic/RuleGenerator.

.NOTES
    Module Name: RulesViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/RuleGenerator

.EXAMPLE
    Import-Module .\RulesViewModel.ps1

    # Initialize and add rules
    Initialize-RulesCollection
    Add-Rule -RuleData $ruleObject
    $displayItems = Get-RuleDisplayItems

.EXAMPLE
    # Filter rules by type
    $filtered = Apply-RuleFilters -RuleType "Publisher" -Action "Allow"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:GeneratedRules = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$script:RuleFilters = [hashtable]::Synchronized(@{
    RuleType = "All"        # All, Publisher, Hash, Path
    Action = "All"          # All, Allow, Deny, Audit
    UserGroup = "All"       # All, Everyone, Administrators, specific group
    Collection = "All"      # All, Exe, Msi, Script, Dll, Appx
    SearchText = ""
})

$script:RuleStatistics = [hashtable]::Synchronized(@{
    TotalRules = 0
    PublisherRules = 0
    HashRules = 0
    PathRules = 0
    AllowRules = 0
    DenyRules = 0
    AuditRules = 0
    ByCollection = @{
        Exe = 0
        Msi = 0
        Script = 0
        Dll = 0
        Appx = 0
    }
})

$script:NextRuleId = 1

# ============================================================
# PUBLIC FUNCTIONS - INITIALIZATION & DATA RETRIEVAL
# ============================================================

function Initialize-RulesCollection {
    <#
    .SYNOPSIS
        Initializes the rules collection

    .DESCRIPTION
        Clears existing rules and resets state to defaults

    .EXAMPLE
        Initialize-RulesCollection
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing rules collection..."

        $script:GeneratedRules.Clear()
        $script:NextRuleId = 1

        # Reset filters
        $script:RuleFilters.RuleType = "All"
        $script:RuleFilters.Action = "All"
        $script:RuleFilters.UserGroup = "All"
        $script:RuleFilters.Collection = "All"
        $script:RuleFilters.SearchText = ""

        # Reset statistics
        Update-RuleStatistics

        Write-Verbose "Rules collection initialized"
        return @{ success = $true; message = "Rules collection initialized" }
    }
    catch {
        Write-Warning "Failed to initialize rules collection: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-RuleDisplayItems {
    <#
    .SYNOPSIS
        Gets formatted rules for DataGrid display

    .DESCRIPTION
        Returns rules formatted with display-friendly properties and current filter applied

    .PARAMETER ApplyFilters
        Whether to apply current filters (default: $true)

    .OUTPUTS
        Array of rule objects formatted for display

    .EXAMPLE
        $items = Get-RuleDisplayItems
        $dataGrid.ItemsSource = $items
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$ApplyFilters = $true
    )

    try {
        Write-Verbose "Getting rule display items (ApplyFilters: $ApplyFilters)..."

        # Get base collection
        $rules = if ($ApplyFilters) {
            Get-FilteredRules
        } else {
            $script:GeneratedRules.ToArray()
        }

        # Format for display
        $displayItems = $rules | ForEach-Object {
            [PSCustomObject]@{
                Id = $_.Id
                RuleType = $_.RuleType
                Action = $_.Action
                Name = $_.Name
                Description = Get-RuleDescription -Rule $_
                Publisher = if ($_.RuleType -eq 'Publisher') { $_.PublisherName } else { '-' }
                Product = if ($_.RuleType -eq 'Publisher') { $_.ProductName } else { '-' }
                Path = if ($_.RuleType -eq 'Path') { $_.PathCondition } else { '-' }
                Hash = if ($_.RuleType -eq 'Hash') { $_.HashValue.Substring(0, [Math]::Min(16, $_.HashValue.Length)) + '...' } else { '-' }
                UserGroup = $_.UserOrGroupSid
                Collection = $_.RuleCollection
                CreatedDate = $_.CreatedDate
                IsEnabled = $_.IsEnabled
                _RawData = $_
            }
        }

        Write-Verbose "Returning $($displayItems.Count) display items"
        return $displayItems
    }
    catch {
        Write-Warning "Failed to get rule display items: $($_.Exception.Message)"
        return @()
    }
}

function Get-AllRules {
    <#
    .SYNOPSIS
        Gets all rules without filtering

    .DESCRIPTION
        Returns the complete rules collection

    .OUTPUTS
        Array of all rule objects

    .EXAMPLE
        $allRules = Get-AllRules
    #>
    [CmdletBinding()]
    param()

    try {
        return $script:GeneratedRules.ToArray()
    }
    catch {
        Write-Warning "Failed to get all rules: $($_.Exception.Message)"
        return @()
    }
}

function Get-RuleById {
    <#
    .SYNOPSIS
        Gets a specific rule by ID

    .PARAMETER RuleId
        The rule ID to retrieve

    .OUTPUTS
        Rule object or $null if not found

    .EXAMPLE
        $rule = Get-RuleById -RuleId 123
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RuleId
    )

    try {
        $rule = $script:GeneratedRules | Where-Object { $_.Id -eq $RuleId } | Select-Object -First 1
        return $rule
    }
    catch {
        Write-Warning "Failed to get rule by ID: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PUBLIC FUNCTIONS - CRUD OPERATIONS
# ============================================================

function Add-Rule {
    <#
    .SYNOPSIS
        Adds a rule to the collection

    .DESCRIPTION
        Adds a new rule with validation and automatic ID assignment

    .PARAMETER RuleData
        Hashtable or PSCustomObject containing rule properties

    .OUTPUTS
        Hashtable with success status and the added rule

    .EXAMPLE
        $rule = @{
            RuleType = 'Publisher'
            Action = 'Allow'
            PublisherName = 'Microsoft Corporation'
            RuleCollection = 'Exe'
        }
        $result = Add-Rule -RuleData $rule
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        $RuleData
    )

    try {
        Write-Verbose "Adding rule to collection..."

        # Validate required fields
        if (-not $RuleData.RuleType) {
            throw "RuleType is required"
        }
        if (-not $RuleData.Action) {
            throw "Action is required"
        }

        # Create rule object
        $rule = [PSCustomObject]@{
            Id = $script:NextRuleId++
            RuleType = $RuleData.RuleType
            Action = $RuleData.Action
            Name = if ($RuleData.Name) { $RuleData.Name } else { "Rule_$($script:NextRuleId - 1)" }
            Description = $RuleData.Description
            PublisherName = $RuleData.PublisherName
            ProductName = $RuleData.ProductName
            BinaryName = $RuleData.BinaryName
            BinaryVersion = $RuleData.BinaryVersion
            PathCondition = $RuleData.PathCondition
            HashValue = $RuleData.HashValue
            HashAlgorithm = if ($RuleData.HashAlgorithm) { $RuleData.HashAlgorithm } else { 'SHA256' }
            UserOrGroupSid = if ($RuleData.UserOrGroupSid) { $RuleData.UserOrGroupSid } else { 'S-1-1-0' }
            RuleCollection = if ($RuleData.RuleCollection) { $RuleData.RuleCollection } else { 'Exe' }
            IsEnabled = if ($null -ne $RuleData.IsEnabled) { $RuleData.IsEnabled } else { $true }
            CreatedDate = Get-Date
            ModifiedDate = Get-Date
            XmlRepresentation = $RuleData.XmlRepresentation
        }

        # Add to collection
        [void]$script:GeneratedRules.Add($rule)

        # Update statistics
        Update-RuleStatistics

        Write-Verbose "Rule added successfully (ID: $($rule.Id))"
        return @{
            success = $true
            message = "Rule added"
            rule = $rule
        }
    }
    catch {
        Write-Warning "Failed to add rule: $($_.Exception.Message)"
        return @{
            success = $false
            message = $_.Exception.Message
            rule = $null
        }
    }
}

function Add-Rules {
    <#
    .SYNOPSIS
        Adds multiple rules to the collection

    .PARAMETER Rules
        Array of rule data objects

    .OUTPUTS
        Hashtable with success status and count of added rules

    .EXAMPLE
        $rules = @($rule1, $rule2, $rule3)
        $result = Add-Rules -Rules $rules
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Rules
    )

    try {
        Write-Verbose "Adding $($Rules.Count) rules to collection..."

        $addedCount = 0
        $failedCount = 0

        foreach ($ruleData in $Rules) {
            $result = Add-Rule -RuleData $ruleData
            if ($result.success) {
                $addedCount++
            } else {
                $failedCount++
            }
        }

        Write-Verbose "Added $addedCount rules ($failedCount failed)"
        return @{
            success = $true
            message = "Added $addedCount rules"
            addedCount = $addedCount
            failedCount = $failedCount
        }
    }
    catch {
        Write-Warning "Failed to add rules: $($_.Exception.Message)"
        return @{
            success = $false
            message = $_.Exception.Message
        }
    }
}

function Remove-Rule {
    <#
    .SYNOPSIS
        Removes a rule from the collection

    .PARAMETER RuleId
        The ID of the rule to remove

    .OUTPUTS
        Hashtable with success status

    .EXAMPLE
        Remove-Rule -RuleId 123
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RuleId
    )

    try {
        Write-Verbose "Removing rule ID: $RuleId..."

        $rule = $script:GeneratedRules | Where-Object { $_.Id -eq $RuleId } | Select-Object -First 1

        if (-not $rule) {
            throw "Rule not found: $RuleId"
        }

        [void]$script:GeneratedRules.Remove($rule)

        # Update statistics
        Update-RuleStatistics

        Write-Verbose "Rule removed successfully"
        return @{ success = $true; message = "Rule removed" }
    }
    catch {
        Write-Warning "Failed to remove rule: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Remove-Rules {
    <#
    .SYNOPSIS
        Removes multiple rules from the collection

    .PARAMETER RuleIds
        Array of rule IDs to remove

    .EXAMPLE
        Remove-Rules -RuleIds @(1, 2, 3)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int[]]$RuleIds
    )

    try {
        Write-Verbose "Removing $($RuleIds.Count) rules..."

        $removedCount = 0
        foreach ($ruleId in $RuleIds) {
            $result = Remove-Rule -RuleId $ruleId
            if ($result.success) {
                $removedCount++
            }
        }

        Write-Verbose "Removed $removedCount rules"
        return @{
            success = $true
            message = "Removed $removedCount rules"
            removedCount = $removedCount
        }
    }
    catch {
        Write-Warning "Failed to remove rules: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Update-Rule {
    <#
    .SYNOPSIS
        Updates an existing rule

    .PARAMETER RuleId
        The ID of the rule to update

    .PARAMETER UpdatedData
        Hashtable containing fields to update

    .EXAMPLE
        Update-Rule -RuleId 123 -UpdatedData @{ Action = 'Deny'; IsEnabled = $false }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RuleId,

        [Parameter(Mandatory)]
        [hashtable]$UpdatedData
    )

    try {
        Write-Verbose "Updating rule ID: $RuleId..."

        $rule = Get-RuleById -RuleId $RuleId

        if (-not $rule) {
            throw "Rule not found: $RuleId"
        }

        # Update allowed fields
        foreach ($key in $UpdatedData.Keys) {
            if ($rule.PSObject.Properties.Name -contains $key -and $key -ne 'Id' -and $key -ne 'CreatedDate') {
                $rule.$key = $UpdatedData[$key]
            }
        }

        $rule.ModifiedDate = Get-Date

        # Update statistics
        Update-RuleStatistics

        Write-Verbose "Rule updated successfully"
        return @{ success = $true; message = "Rule updated"; rule = $rule }
    }
    catch {
        Write-Warning "Failed to update rule: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Clear-Rules {
    <#
    .SYNOPSIS
        Clears all rules from the collection

    .EXAMPLE
        Clear-Rules
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing all rules..."

        $count = $script:GeneratedRules.Count
        $script:GeneratedRules.Clear()
        $script:NextRuleId = 1

        Update-RuleStatistics

        Write-Verbose "Cleared $count rules"
        return @{ success = $true; message = "Cleared $count rules"; count = $count }
    }
    catch {
        Write-Warning "Failed to clear rules: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - FILTERING & STATISTICS
# ============================================================

function Apply-RuleFilters {
    <#
    .SYNOPSIS
        Applies filters to the rules collection

    .PARAMETER RuleType
        Filter by rule type: All, Publisher, Hash, Path

    .PARAMETER Action
        Filter by action: All, Allow, Deny, Audit

    .PARAMETER UserGroup
        Filter by user/group

    .PARAMETER Collection
        Filter by collection: All, Exe, Msi, Script, Dll, Appx

    .PARAMETER SearchText
        Filter by search text (matches name, description, publisher, path)

    .EXAMPLE
        Apply-RuleFilters -RuleType "Publisher" -Action "Allow"
        $filtered = Get-RuleDisplayItems
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet("All", "Publisher", "Hash", "Path")]
        [string]$RuleType,

        [Parameter()]
        [ValidateSet("All", "Allow", "Deny", "Audit")]
        [string]$Action,

        [Parameter()]
        [string]$UserGroup,

        [Parameter()]
        [ValidateSet("All", "Exe", "Msi", "Script", "Dll", "Appx")]
        [string]$Collection,

        [Parameter()]
        [string]$SearchText
    )

    try {
        Write-Verbose "Applying rule filters..."

        if ($RuleType) { $script:RuleFilters.RuleType = $RuleType }
        if ($Action) { $script:RuleFilters.Action = $Action }
        if ($UserGroup) { $script:RuleFilters.UserGroup = $UserGroup }
        if ($Collection) { $script:RuleFilters.Collection = $Collection }
        if ($null -ne $SearchText) { $script:RuleFilters.SearchText = $SearchText }

        Write-Verbose "Filters applied: Type=$($script:RuleFilters.RuleType), Action=$($script:RuleFilters.Action)"
        return @{ success = $true; message = "Filters applied" }
    }
    catch {
        Write-Warning "Failed to apply filters: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-RuleStatistics {
    <#
    .SYNOPSIS
        Gets statistics about the rules collection

    .OUTPUTS
        Hashtable containing rule counts by various categories

    .EXAMPLE
        $stats = Get-RuleStatistics
        Write-Host "Total Rules: $($stats.TotalRules)"
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            TotalRules = $script:RuleStatistics.TotalRules
            PublisherRules = $script:RuleStatistics.PublisherRules
            HashRules = $script:RuleStatistics.HashRules
            PathRules = $script:RuleStatistics.PathRules
            AllowRules = $script:RuleStatistics.AllowRules
            DenyRules = $script:RuleStatistics.DenyRules
            AuditRules = $script:RuleStatistics.AuditRules
            ByCollection = $script:RuleStatistics.ByCollection.Clone()
        }
    }
    catch {
        Write-Warning "Failed to get rule statistics: $($_.Exception.Message)"
        return @{ TotalRules = 0 }
    }
}

function Export-RulesToXml {
    <#
    .SYNOPSIS
        Exports rules to AppLocker XML format

    .OUTPUTS
        XML string containing all rules

    .EXAMPLE
        $xml = Export-RulesToXml
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Exporting rules to XML..."

        # Group rules by collection type
        $rulesByCollection = $script:GeneratedRules | Group-Object -Property RuleCollection

        # Build XML (placeholder - would call BusinessLogic)
        $xml = "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<AppLockerPolicy Version=`"1`">`n"

        # Add rule collections
        # ... XML building logic would go here

        $xml += "</AppLockerPolicy>"

        Write-Verbose "Exported $($script:GeneratedRules.Count) rules to XML"
        return $xml
    }
    catch {
        Write-Warning "Failed to export rules to XML: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Get-FilteredRules {
    [CmdletBinding()]
    param()

    $filtered = $script:GeneratedRules.ToArray()

    # Apply RuleType filter
    if ($script:RuleFilters.RuleType -ne "All") {
        $filtered = $filtered | Where-Object { $_.RuleType -eq $script:RuleFilters.RuleType }
    }

    # Apply Action filter
    if ($script:RuleFilters.Action -ne "All") {
        $filtered = $filtered | Where-Object { $_.Action -eq $script:RuleFilters.Action }
    }

    # Apply Collection filter
    if ($script:RuleFilters.Collection -ne "All") {
        $filtered = $filtered | Where-Object { $_.RuleCollection -eq $script:RuleFilters.Collection }
    }

    # Apply UserGroup filter
    if ($script:RuleFilters.UserGroup -ne "All") {
        $filtered = $filtered | Where-Object { $_.UserOrGroupSid -eq $script:RuleFilters.UserGroup }
    }

    # Apply search text filter
    if ($script:RuleFilters.SearchText) {
        $searchText = $script:RuleFilters.SearchText.ToLower()
        $filtered = $filtered | Where-Object {
            $_.Name.ToLower().Contains($searchText) -or
            ($_.Description -and $_.Description.ToLower().Contains($searchText)) -or
            ($_.PublisherName -and $_.PublisherName.ToLower().Contains($searchText)) -or
            ($_.PathCondition -and $_.PathCondition.ToLower().Contains($searchText))
        }
    }

    return $filtered
}

function Update-RuleStatistics {
    [CmdletBinding()]
    param()

    $rules = $script:GeneratedRules.ToArray()

    $script:RuleStatistics.TotalRules = $rules.Count
    $script:RuleStatistics.PublisherRules = ($rules | Where-Object { $_.RuleType -eq 'Publisher' }).Count
    $script:RuleStatistics.HashRules = ($rules | Where-Object { $_.RuleType -eq 'Hash' }).Count
    $script:RuleStatistics.PathRules = ($rules | Where-Object { $_.RuleType -eq 'Path' }).Count
    $script:RuleStatistics.AllowRules = ($rules | Where-Object { $_.Action -eq 'Allow' }).Count
    $script:RuleStatistics.DenyRules = ($rules | Where-Object { $_.Action -eq 'Deny' }).Count
    $script:RuleStatistics.AuditRules = ($rules | Where-Object { $_.Action -eq 'Audit' }).Count

    $script:RuleStatistics.ByCollection.Exe = ($rules | Where-Object { $_.RuleCollection -eq 'Exe' }).Count
    $script:RuleStatistics.ByCollection.Msi = ($rules | Where-Object { $_.RuleCollection -eq 'Msi' }).Count
    $script:RuleStatistics.ByCollection.Script = ($rules | Where-Object { $_.RuleCollection -eq 'Script' }).Count
    $script:RuleStatistics.ByCollection.Dll = ($rules | Where-Object { $_.RuleCollection -eq 'Dll' }).Count
    $script:RuleStatistics.ByCollection.Appx = ($rules | Where-Object { $_.RuleCollection -eq 'Appx' }).Count
}

function Get-RuleDescription {
    param($Rule)

    if ($Rule.Description) {
        return $Rule.Description
    }

    switch ($Rule.RuleType) {
        'Publisher' {
            return "Publisher: $($Rule.PublisherName)"
        }
        'Hash' {
            return "Hash: $($Rule.HashAlgorithm)"
        }
        'Path' {
            return "Path: $($Rule.PathCondition)"
        }
        default {
            return "Unknown rule type"
        }
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-RulesCollection',
    'Get-RuleDisplayItems',
    'Get-AllRules',
    'Get-RuleById',
    'Add-Rule',
    'Add-Rules',
    'Remove-Rule',
    'Remove-Rules',
    'Update-Rule',
    'Clear-Rules',
    'Apply-RuleFilters',
    'Get-RuleStatistics',
    'Export-RulesToXml'
)
