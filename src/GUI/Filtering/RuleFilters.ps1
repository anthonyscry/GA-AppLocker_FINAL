<#
.SYNOPSIS
    Rule filtering and search logic

.DESCRIPTION
    Provides filtering functions for AppLocker rules with support for multiple
    filter criteria including type, action, group, and text search.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Filter-RulesDataGrid {
    <#
    .SYNOPSIS
        Filters rules in the DataGrid based on multiple criteria

    .DESCRIPTION
        Applies real-time filtering to the rules DataGrid using type, action, group,
        and search text filters. Updates the DataGrid display and filter count.

    .PARAMETER DataGrid
        The WPF DataGrid control containing rules

    .PARAMETER Rules
        Array of rule objects to filter

    .PARAMETER RuleType
        Filter by rule type (Publisher, Hash, Path, or empty for all)

    .PARAMETER Action
        Filter by action (Allow, Deny, or empty for all)

    .PARAMETER Group
        Filter by group name (partial match supported)

    .PARAMETER SearchText
        Search text to match against rule name, publisher, or path

    .EXAMPLE
        Filter-RulesDataGrid -DataGrid $grid -Rules $allRules -RuleType "Publisher" -Action "Allow"
    #>
    param(
        [Parameter(Mandatory=$false)]
        $DataGrid,

        [Parameter(Mandatory=$false)]
        [array]$Rules = @(),

        [Parameter(Mandatory=$false)]
        [string]$RuleType = "",

        [Parameter(Mandatory=$false)]
        [string]$Action = "",

        [Parameter(Mandatory=$false)]
        [string]$Group = "",

        [Parameter(Mandatory=$false)]
        [string]$SearchText = ""
    )

    if ($null -eq $DataGrid) {
        Write-Warning "DataGrid is null, cannot filter"
        return
    }

    # Start with all rules
    $filteredRules = @($Rules)

    # Apply type filter
    if (-not [string]::IsNullOrWhiteSpace($RuleType)) {
        $filteredRules = $filteredRules | Where-Object { $_.Type -eq $RuleType }
    }

    # Apply action filter
    if (-not [string]::IsNullOrWhiteSpace($Action)) {
        $filteredRules = $filteredRules | Where-Object { $_.Action -eq $Action }
    }

    # Apply group filter
    if (-not [string]::IsNullOrWhiteSpace($Group)) {
        $filteredRules = $filteredRules | Where-Object { $_.Group -like "*$Group*" }
    }

    # Apply search text filter
    if (-not [string]::IsNullOrWhiteSpace($SearchText)) {
        $filteredRules = $filteredRules | Where-Object {
            $_.Name -like "*$SearchText*" -or
            $_.Group -like "*$SearchText*" -or
            $_.Publisher -like "*$SearchText*" -or
            $_.Path -like "*$SearchText*"
        }
    }

    # Update DataGrid
    $DataGrid.ItemsSource = $filteredRules

    # Update filter count if control exists
    if ($null -ne $RulesFilterCount) {
        if ($filteredRules.Count -lt $Rules.Count) {
            $RulesFilterCount.Text = "$($filteredRules.Count) of $($Rules.Count)"
        } else {
            $RulesFilterCount.Text = ""
        }
    }

    return $filteredRules
}

function Get-FilteredRules {
    <#
    .SYNOPSIS
        Returns filtered rule collection

    .DESCRIPTION
        Applies filters to a rule collection and returns the filtered results.
        Does not modify UI controls - pure data filtering.

    .PARAMETER Rules
        Array of rule objects to filter

    .PARAMETER Filters
        Hashtable of filter criteria with keys: Type, Action, Group, Search

    .OUTPUTS
        Returns filtered array of rules

    .EXAMPLE
        $filters = @{ Type = "Publisher"; Action = "Allow"; Search = "Microsoft" }
        $filtered = Get-FilteredRules -Rules $allRules -Filters $filters
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Rules,

        [Parameter(Mandatory=$true)]
        [hashtable]$Filters
    )

    $filtered = @($Rules)

    # Type filter
    if ($Filters.ContainsKey('Type') -and -not [string]::IsNullOrWhiteSpace($Filters.Type)) {
        $filtered = $filtered | Where-Object { $_.type -eq $Filters.Type }
    }

    # Action filter
    if ($Filters.ContainsKey('Action') -and -not [string]::IsNullOrWhiteSpace($Filters.Action)) {
        $filtered = $filtered | Where-Object { $_.action -eq $Filters.Action }
    }

    # Group filter
    if ($Filters.ContainsKey('Group') -and -not [string]::IsNullOrWhiteSpace($Filters.Group)) {
        $groupFilter = $Filters.Group
        $filtered = $filtered | Where-Object {
            $_.userOrGroupSid -like "*$groupFilter*" -or
            $_.Group -like "*$groupFilter*"
        }
    }

    # Search filter
    if ($Filters.ContainsKey('Search') -and -not [string]::IsNullOrWhiteSpace($Filters.Search)) {
        $searchText = $Filters.Search.ToLower()
        $filtered = $filtered | Where-Object {
            $_.publisher -like "*$searchText*" -or
            $_.type -like "*$searchText*" -or
            $_.path -like "*$searchText*" -or
            $_.fileName -like "*$searchText*" -or
            $_.publisherName -like "*$searchText*"
        }
    }

    return $filtered
}

function Get-RuleFilterCounts {
    <#
    .SYNOPSIS
        Calculates filter counts for rules

    .DESCRIPTION
        Returns counts of rules grouped by various filter categories.

    .PARAMETER Rules
        Array of rule objects

    .OUTPUTS
        Returns hashtable with counts by Type, Action, and Group

    .EXAMPLE
        $counts = Get-RuleFilterCounts -Rules $allRules
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Rules
    )

    $counts = @{
        Total = $Rules.Count
        ByType = @{}
        ByAction = @{}
        ByGroup = @{}
    }

    if ($Rules.Count -eq 0) {
        return $counts
    }

    # Count by type
    $typeGroups = $Rules | Group-Object -Property type
    foreach ($group in $typeGroups) {
        $counts.ByType[$group.Name] = $group.Count
    }

    # Count by action
    $actionGroups = $Rules | Group-Object -Property action
    foreach ($group in $actionGroups) {
        $counts.ByAction[$group.Name] = $group.Count
    }

    # Count by group/SID
    $groupGroups = $Rules | Group-Object -Property userOrGroupSid
    foreach ($group in $groupGroups) {
        $counts.ByGroup[$group.Name] = $group.Count
    }

    return $counts
}

function Apply-FilterToRules {
    <#
    .SYNOPSIS
        Applies filter to rules output display

    .DESCRIPTION
        Filters rules and updates the text output display (not DataGrid).
        Used for text-based rule display in the GUI.

    .PARAMETER Controls
        Hashtable of UI controls (RulesSearchBox, RulesOutput)

    .PARAMETER Filters
        Hashtable of filter values

    .EXAMPLE
        Apply-FilterToRules -Controls @{SearchBox=$box; Output=$output} -Filters @{Search="Microsoft"}
    #>
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$Controls = @{},

        [Parameter(Mandatory=$false)]
        [hashtable]$Filters = @{}
    )

    if (-not $Controls.ContainsKey('SearchBox') -or -not $Controls.ContainsKey('Output')) {
        Write-Warning "Required controls not provided"
        return
    }

    $searchBox = $Controls.SearchBox
    $output = $Controls.Output

    $filterText = if ($Filters.ContainsKey('Search')) { $Filters.Search } else { "" }

    if ([string]::IsNullOrWhiteSpace($filterText) -or $filterText -eq "Filter rules/artifacts...") {
        # Show all rules
        if ($script:GeneratedRules.Count -gt 0) {
            $modeText = if ($script:AuditModeEnabled) { "AUDIT ([!])" } else { "ENFORCE ([X])" }
            $output.Text = "=== RULE COLLECTION - $modeText ===`n`n"
            $output.Text += "Total Rules: $($script:GeneratedRules.Count)`n`n"

            foreach ($rule in $script:GeneratedRules) {
                $action = if ($script:AuditModeEnabled) { "AUDIT" } else { $rule.action }
                $output.Text += "[$action] [$($rule.type)] $($rule.publisher)`n"
            }
        }
        return
    }

    # Filter rules
    $filterText = $filterText.ToLower()
    $filteredRules = $script:GeneratedRules | Where-Object {
        $_.publisher -like "*$filterText*" -or
        $_.type -like "*$filterText*" -or
        $_.path -like "*$filterText*" -or
        $_.fileName -like "*$filterText*"
    }

    $modeText = if ($script:AuditModeEnabled) { "AUDIT ([!])" } else { "ENFORCE ([X])" }
    $output.Text = "=== FILTERED RESULTS ($($filteredRules.Count)/$($script:GeneratedRules.Count)) - $modeText ===`n`n"
    $output.Text += "Filter: '$filterText'`n`n"

    if ($filteredRules.Count -eq 0) {
        $output.Text += "No matching rules found."
    } else {
        foreach ($rule in $filteredRules) {
            $action = if ($script:AuditModeEnabled) { "AUDIT" } else { $rule.action }
            $output.Text += "[$action] [$($rule.type)] $($rule.publisher)`n"
        }
    }
}

function Sort-RulesByProperty {
    <#
    .SYNOPSIS
        Sorts rules by specified property

    .DESCRIPTION
        Sorts rule collection by a given property in ascending or descending order.

    .PARAMETER Rules
        Array of rule objects

    .PARAMETER Property
        Property name to sort by (Type, Action, Publisher, etc.)

    .PARAMETER Descending
        Sort in descending order (default: ascending)

    .OUTPUTS
        Returns sorted array of rules

    .EXAMPLE
        $sorted = Sort-RulesByProperty -Rules $allRules -Property "Type"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Rules,

        [Parameter(Mandatory=$true)]
        [string]$Property,

        [Parameter(Mandatory=$false)]
        [switch]$Descending
    )

    if ($Descending) {
        return $Rules | Sort-Object -Property $Property -Descending
    } else {
        return $Rules | Sort-Object -Property $Property
    }
}

Export-ModuleMember -Function Filter-RulesDataGrid, Get-FilteredRules, Get-RuleFilterCounts, Apply-FilterToRules, Sort-RulesByProperty
