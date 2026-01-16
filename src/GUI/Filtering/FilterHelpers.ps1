<#
.SYNOPSIS
    Filter UI management helpers

.DESCRIPTION
    Provides helper functions for managing filter UI controls, including
    clearing filters, updating filter counts, and managing filter state.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Clear-AllFilters {
    <#
    .SYNOPSIS
        Resets all filter controls to default state

    .DESCRIPTION
        Clears all filter selections and search boxes, resetting the UI to show all items.

    .PARAMETER Controls
        Hashtable of filter control references

    .EXAMPLE
        Clear-AllFilters -Controls @{TypeFilter=$combo1; SearchBox=$text1}
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Controls
    )

    try {
        # Clear combo box selections
        if ($Controls.ContainsKey('TypeFilter') -and $null -ne $Controls.TypeFilter) {
            $Controls.TypeFilter.SelectedIndex = 0  # Select "All" or first item
        }

        if ($Controls.ContainsKey('ActionFilter') -and $null -ne $Controls.ActionFilter) {
            $Controls.ActionFilter.SelectedIndex = 0
        }

        if ($Controls.ContainsKey('GroupFilter') -and $null -ne $Controls.GroupFilter) {
            $Controls.GroupFilter.SelectedIndex = 0
        }

        if ($Controls.ContainsKey('StatusFilter') -and $null -ne $Controls.StatusFilter) {
            $Controls.StatusFilter.SelectedIndex = 0
        }

        # Clear search text boxes
        if ($Controls.ContainsKey('SearchBox') -and $null -ne $Controls.SearchBox) {
            $Controls.SearchBox.Text = ""
        }

        if ($Controls.ContainsKey('SearchText') -and $null -ne $Controls.SearchText) {
            $Controls.SearchText.Text = ""
        }

        # Clear date pickers
        if ($Controls.ContainsKey('DateFrom') -and $null -ne $Controls.DateFrom) {
            $Controls.DateFrom.SelectedDate = $null
        }

        if ($Controls.ContainsKey('DateTo') -and $null -ne $Controls.DateTo) {
            $Controls.DateTo.SelectedDate = $null
        }

        # Clear filter count display
        if ($Controls.ContainsKey('FilterCount') -and $null -ne $Controls.FilterCount) {
            $Controls.FilterCount.Text = ""
        }

        Write-Verbose "All filters cleared"
    }
    catch {
        Write-Warning "Error clearing filters: $_"
    }
}

function Update-FilterCounts {
    <#
    .SYNOPSIS
        Updates filter count badges in the UI

    .DESCRIPTION
        Updates text controls showing the number of items matching current filters.

    .PARAMETER Controls
        Hashtable of UI control references

    .PARAMETER Counts
        Hashtable with Total and Filtered counts

    .EXAMPLE
        Update-FilterCounts -Controls @{FilterCount=$label} -Counts @{Total=100; Filtered=25}
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Controls,

        [Parameter(Mandatory=$true)]
        [hashtable]$Counts
    )

    try {
        $total = if ($Counts.ContainsKey('Total')) { $Counts.Total } else { 0 }
        $filtered = if ($Counts.ContainsKey('Filtered')) { $Counts.Filtered } else { $total }

        if ($Controls.ContainsKey('FilterCount') -and $null -ne $Controls.FilterCount) {
            if ($filtered -lt $total) {
                $Controls.FilterCount.Text = "Showing $filtered of $total"
            } else {
                $Controls.FilterCount.Text = ""
            }
        }

        if ($Controls.ContainsKey('TotalCount') -and $null -ne $Controls.TotalCount) {
            $Controls.TotalCount.Text = "$total total"
        }

        if ($Controls.ContainsKey('FilteredCount') -and $null -ne $Controls.FilteredCount) {
            $Controls.FilteredCount.Text = "$filtered items"
        }

        Write-Verbose "Filter counts updated: $filtered of $total"
    }
    catch {
        Write-Warning "Error updating filter counts: $_"
    }
}

function Get-FilterState {
    <#
    .SYNOPSIS
        Retrieves current filter state from UI controls

    .DESCRIPTION
        Reads current values from filter controls and returns them as a hashtable.

    .PARAMETER Controls
        Hashtable of UI control references

    .OUTPUTS
        Returns hashtable with current filter values

    .EXAMPLE
        $state = Get-FilterState -Controls @{TypeFilter=$combo; SearchBox=$text}
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Controls
    )

    $state = @{}

    try {
        # Get combo box selections
        if ($Controls.ContainsKey('TypeFilter') -and $null -ne $Controls.TypeFilter) {
            $item = $Controls.TypeFilter.SelectedItem
            $state.Type = if ($item -and $item.Tag) { $item.Tag } else { "" }
        }

        if ($Controls.ContainsKey('ActionFilter') -and $null -ne $Controls.ActionFilter) {
            $item = $Controls.ActionFilter.SelectedItem
            $state.Action = if ($item -and $item.Tag) { $item.Tag } else { "" }
        }

        if ($Controls.ContainsKey('GroupFilter') -and $null -ne $Controls.GroupFilter) {
            $item = $Controls.GroupFilter.SelectedItem
            $state.Group = if ($item -and $item.Tag) { $item.Tag } else { "" }
        }

        # Get search text
        if ($Controls.ContainsKey('SearchBox') -and $null -ne $Controls.SearchBox) {
            $text = $Controls.SearchBox.Text
            $state.Search = if ($text -and $text -ne "Search..." -and $text -ne "Filter...") { $text } else { "" }
        }

        # Get date range
        if ($Controls.ContainsKey('DateFrom') -and $null -ne $Controls.DateFrom) {
            $state.DateFrom = $Controls.DateFrom.SelectedDate
        }

        if ($Controls.ContainsKey('DateTo') -and $null -ne $Controls.DateTo) {
            $state.DateTo = $Controls.DateTo.SelectedDate
        }

        Write-Verbose "Filter state retrieved"
    }
    catch {
        Write-Warning "Error getting filter state: $_"
    }

    return $state
}

function Set-FilterState {
    <#
    .SYNOPSIS
        Sets filter controls to specified state

    .DESCRIPTION
        Applies saved filter state to UI controls.

    .PARAMETER Controls
        Hashtable of UI control references

    .PARAMETER State
        Hashtable of filter values to apply

    .EXAMPLE
        Set-FilterState -Controls @{SearchBox=$text} -State @{Search="Microsoft"}
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Controls,

        [Parameter(Mandatory=$true)]
        [hashtable]$State
    )

    try {
        # Set search text
        if ($State.ContainsKey('Search') -and $Controls.ContainsKey('SearchBox') -and $null -ne $Controls.SearchBox) {
            $Controls.SearchBox.Text = $State.Search
        }

        # Set date range
        if ($State.ContainsKey('DateFrom') -and $Controls.ContainsKey('DateFrom') -and $null -ne $Controls.DateFrom) {
            $Controls.DateFrom.SelectedDate = $State.DateFrom
        }

        if ($State.ContainsKey('DateTo') -and $Controls.ContainsKey('DateTo') -and $null -ne $Controls.DateTo) {
            $Controls.DateTo.SelectedDate = $State.DateTo
        }

        # Set combo box selections (requires finding matching item)
        if ($State.ContainsKey('Type') -and $Controls.ContainsKey('TypeFilter') -and $null -ne $Controls.TypeFilter) {
            foreach ($item in $Controls.TypeFilter.Items) {
                if ($item.Tag -eq $State.Type) {
                    $Controls.TypeFilter.SelectedItem = $item
                    break
                }
            }
        }

        Write-Verbose "Filter state applied"
    }
    catch {
        Write-Warning "Error setting filter state: $_"
    }
}

function Test-FilterActive {
    <#
    .SYNOPSIS
        Checks if any filters are currently active

    .DESCRIPTION
        Determines whether any filter controls have non-default values.

    .PARAMETER State
        Hashtable of current filter state

    .OUTPUTS
        Returns $true if any filter is active, $false otherwise

    .EXAMPLE
        if (Test-FilterActive -State $currentState) { Write-Host "Filters active" }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$State
    )

    $hasActiveFilter = $false

    foreach ($key in $State.Keys) {
        $value = $State[$key]

        if ($key -eq 'DateFrom' -or $key -eq 'DateTo') {
            if ($value -and $value -gt [datetime]::MinValue) {
                $hasActiveFilter = $true
                break
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($value)) {
            $hasActiveFilter = $true
            break
        }
    }

    return $hasActiveFilter
}

function Initialize-FilterControls {
    <#
    .SYNOPSIS
        Initializes filter controls with default values

    .DESCRIPTION
        Sets up filter controls with placeholder text and default selections.

    .PARAMETER Controls
        Hashtable of UI control references

    .PARAMETER Placeholders
        Hashtable of placeholder text values

    .EXAMPLE
        Initialize-FilterControls -Controls @{SearchBox=$text} -Placeholders @{Search="Search..."}
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Controls,

        [Parameter(Mandatory=$false)]
        [hashtable]$Placeholders = @{}
    )

    try {
        # Set search box placeholders
        if ($Controls.ContainsKey('SearchBox') -and $null -ne $Controls.SearchBox) {
            $placeholder = if ($Placeholders.ContainsKey('Search')) { $Placeholders.Search } else { "Search..." }
            $Controls.SearchBox.Text = $placeholder
            $Controls.SearchBox.Foreground = "#8B949E"  # Gray color
        }

        # Select first item (usually "All") in combo boxes
        if ($Controls.ContainsKey('TypeFilter') -and $null -ne $Controls.TypeFilter -and $Controls.TypeFilter.Items.Count -gt 0) {
            $Controls.TypeFilter.SelectedIndex = 0
        }

        if ($Controls.ContainsKey('ActionFilter') -and $null -ne $Controls.ActionFilter -and $Controls.ActionFilter.Items.Count -gt 0) {
            $Controls.ActionFilter.SelectedIndex = 0
        }

        if ($Controls.ContainsKey('GroupFilter') -and $null -ne $Controls.GroupFilter -and $Controls.GroupFilter.Items.Count -gt 0) {
            $Controls.GroupFilter.SelectedIndex = 0
        }

        Write-Verbose "Filter controls initialized"
    }
    catch {
        Write-Warning "Error initializing filter controls: $_"
    }
}

function Format-FilterSummary {
    <#
    .SYNOPSIS
        Formats a summary of active filters

    .DESCRIPTION
        Creates a human-readable summary of currently active filters.

    .PARAMETER State
        Hashtable of current filter state

    .OUTPUTS
        Returns formatted string describing active filters

    .EXAMPLE
        $summary = Format-FilterSummary -State $currentState
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$State
    )

    $filters = @()

    if ($State.ContainsKey('Type') -and -not [string]::IsNullOrWhiteSpace($State.Type)) {
        $filters += "Type: $($State.Type)"
    }

    if ($State.ContainsKey('Action') -and -not [string]::IsNullOrWhiteSpace($State.Action)) {
        $filters += "Action: $($State.Action)"
    }

    if ($State.ContainsKey('Group') -and -not [string]::IsNullOrWhiteSpace($State.Group)) {
        $filters += "Group: $($State.Group)"
    }

    if ($State.ContainsKey('Search') -and -not [string]::IsNullOrWhiteSpace($State.Search)) {
        $filters += "Search: '$($State.Search)'"
    }

    if ($State.ContainsKey('DateFrom') -and $State.DateFrom -gt [datetime]::MinValue) {
        $filters += "From: $($State.DateFrom.ToString('yyyy-MM-dd'))"
    }

    if ($State.ContainsKey('DateTo') -and $State.DateTo -gt [datetime]::MinValue) {
        $filters += "To: $($State.DateTo.ToString('yyyy-MM-dd'))"
    }

    if ($filters.Count -eq 0) {
        return "No filters active"
    }

    return "Active filters: " + ($filters -join ", ")
}

Export-ModuleMember -Function Clear-AllFilters, Update-FilterCounts, Get-FilterState, Set-FilterState, Test-FilterActive, Initialize-FilterControls, Format-FilterSummary
