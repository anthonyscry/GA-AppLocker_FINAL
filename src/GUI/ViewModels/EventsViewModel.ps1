<#
.SYNOPSIS
    Events collection management ViewModel

.DESCRIPTION
    Manages AppLocker events collection for the Event Monitor panel.
    Provides filtering, aggregation, deduplication, and formatting for event display.

.NOTES
    Module Name: EventsViewModel
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: BusinessLogic/EventProcessor

.EXAMPLE
    Import-Module .\EventsViewModel.ps1

    # Initialize and add events
    Initialize-EventsCollection
    Add-Events -Events $eventArray
    $displayItems = Get-EventDisplayItems

.EXAMPLE
    # Filter events by type
    Apply-EventFilters -EventType "Blocked"
    $stats = Get-EventStatistics

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# SCRIPT-SCOPE STATE
# ============================================================

$script:AllEvents = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$script:EventFilters = [hashtable]::Synchronized(@{
    EventType = "All"       # All, Allowed, Blocked, Audit
    ComputerName = "All"
    Publisher = "All"
    DateRange = "All"       # Last Hour, Last 24 Hours, Last 7 Days, All
    SearchText = ""
    ShowDuplicates = $false
})

$script:EventStatistics = [hashtable]::Synchronized(@{
    TotalEvents = 0
    AllowedEvents = 0
    BlockedEvents = 0
    AuditEvents = 0
    UniqueApplications = 0
    UniquePublishers = 0
    UniqueComputers = 0
    OldestEvent = $null
    NewestEvent = $null
})

$script:DeduplicationCache = [hashtable]::Synchronized(@{})

# ============================================================
# PUBLIC FUNCTIONS - INITIALIZATION & DATA RETRIEVAL
# ============================================================

function Initialize-EventsCollection {
    <#
    .SYNOPSIS
        Initializes the events collection

    .DESCRIPTION
        Clears existing events and resets state to defaults

    .EXAMPLE
        Initialize-EventsCollection
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Initializing events collection..."

        $script:AllEvents.Clear()
        $script:DeduplicationCache.Clear()

        # Reset filters
        $script:EventFilters.EventType = "All"
        $script:EventFilters.ComputerName = "All"
        $script:EventFilters.Publisher = "All"
        $script:EventFilters.DateRange = "All"
        $script:EventFilters.SearchText = ""
        $script:EventFilters.ShowDuplicates = $false

        # Reset statistics
        Update-EventStatistics

        Write-Verbose "Events collection initialized"
        return @{ success = $true; message = "Events collection initialized" }
    }
    catch {
        Write-Warning "Failed to initialize events collection: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-EventDisplayItems {
    <#
    .SYNOPSIS
        Gets formatted events for display

    .DESCRIPTION
        Returns events formatted for DataGrid display with current filters applied

    .PARAMETER ApplyFilters
        Whether to apply current filters (default: $true)

    .PARAMETER MaxItems
        Maximum number of items to return (default: unlimited)

    .OUTPUTS
        Array of event objects formatted for display

    .EXAMPLE
        $items = Get-EventDisplayItems -MaxItems 1000
        $dataGrid.ItemsSource = $items
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$ApplyFilters = $true,

        [Parameter()]
        [int]$MaxItems = 0
    )

    try {
        Write-Verbose "Getting event display items (ApplyFilters: $ApplyFilters)..."

        # Get base collection
        $events = if ($ApplyFilters) {
            Get-FilteredEvents
        } else {
            $script:AllEvents.ToArray()
        }

        # Apply deduplication if enabled
        if (-not $script:EventFilters.ShowDuplicates) {
            $events = Get-DeduplicatedEvents -Events $events
        }

        # Limit results if specified
        if ($MaxItems -gt 0 -and $events.Count -gt $MaxItems) {
            $events = $events | Select-Object -First $MaxItems
        }

        # Format for display
        $displayItems = $events | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                EventType = Get-EventTypeName -EventId $_.EventId
                EventId = $_.EventId
                ComputerName = $_.ComputerName
                User = $_.User
                FilePath = $_.FilePath
                FileName = if ($_.FilePath) { Split-Path -Leaf $_.FilePath } else { '-' }
                Publisher = if ($_.Publisher) { $_.Publisher } else { 'Unknown' }
                FileHash = if ($_.FileHash) { $_.FileHash.Substring(0, [Math]::Min(16, $_.FileHash.Length)) + '...' } else { '-' }
                RuleId = $_.RuleId
                RuleName = $_.RuleName
                PolicyName = $_.PolicyName
                DuplicateCount = if ($_.DuplicateCount) { $_.DuplicateCount } else { 1 }
                _RawData = $_
            }
        }

        Write-Verbose "Returning $($displayItems.Count) display items"
        return $displayItems
    }
    catch {
        Write-Warning "Failed to get event display items: $($_.Exception.Message)"
        return @()
    }
}

function Get-AllEvents {
    <#
    .SYNOPSIS
        Gets all events without filtering

    .DESCRIPTION
        Returns the complete events collection

    .OUTPUTS
        Array of all event objects

    .EXAMPLE
        $allEvents = Get-AllEvents
    #>
    [CmdletBinding()]
    param()

    try {
        return $script:AllEvents.ToArray()
    }
    catch {
        Write-Warning "Failed to get all events: $($_.Exception.Message)"
        return @()
    }
}

# ============================================================
# PUBLIC FUNCTIONS - CRUD OPERATIONS
# ============================================================

function Add-Events {
    <#
    .SYNOPSIS
        Adds events to the collection

    .DESCRIPTION
        Appends new events with deduplication support

    .PARAMETER Events
        Array of event objects to add

    .PARAMETER EnableDeduplication
        Whether to check for and track duplicates (default: $true)

    .OUTPUTS
        Hashtable with success status and count of added events

    .EXAMPLE
        $events = Get-AppLockerEvents -MaxEvents 100
        Add-Events -Events $events.data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Events,

        [Parameter()]
        [bool]$EnableDeduplication = $true
    )

    try {
        Write-Verbose "Adding $($Events.Count) events to collection..."

        $addedCount = 0
        $duplicateCount = 0

        foreach ($event in $Events) {
            # Validate event has required properties
            if (-not $event.TimeCreated -or -not $event.EventId) {
                Write-Verbose "Skipping invalid event (missing TimeCreated or EventId)"
                continue
            }

            # Check for duplicates if enabled
            if ($EnableDeduplication) {
                $dedupKey = Get-DeduplicationKey -Event $event

                if ($script:DeduplicationCache.ContainsKey($dedupKey)) {
                    # Update duplicate count
                    $existingEvent = $script:DeduplicationCache[$dedupKey]
                    if (-not $existingEvent.DuplicateCount) {
                        $existingEvent.DuplicateCount = 1
                    }
                    $existingEvent.DuplicateCount++
                    $duplicateCount++
                    continue
                }

                # Track in deduplication cache
                $script:DeduplicationCache[$dedupKey] = $event
            }

            # Add to collection
            [void]$script:AllEvents.Add($event)
            $addedCount++
        }

        # Update statistics
        Update-EventStatistics

        Write-Verbose "Added $addedCount events ($duplicateCount duplicates skipped)"
        return @{
            success = $true
            message = "Added $addedCount events"
            addedCount = $addedCount
            duplicateCount = $duplicateCount
        }
    }
    catch {
        Write-Warning "Failed to add events: $($_.Exception.Message)"
        return @{
            success = $false
            message = $_.Exception.Message
        }
    }
}

function Clear-Events {
    <#
    .SYNOPSIS
        Clears all events from the collection

    .EXAMPLE
        Clear-Events
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Verbose "Clearing all events..."

        $count = $script:AllEvents.Count
        $script:AllEvents.Clear()
        $script:DeduplicationCache.Clear()

        Update-EventStatistics

        Write-Verbose "Cleared $count events"
        return @{ success = $true; message = "Cleared $count events"; count = $count }
    }
    catch {
        Write-Warning "Failed to clear events: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Remove-OldEvents {
    <#
    .SYNOPSIS
        Removes events older than specified date

    .PARAMETER OlderThan
        Remove events older than this date

    .EXAMPLE
        Remove-OldEvents -OlderThan (Get-Date).AddDays(-30)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$OlderThan
    )

    try {
        Write-Verbose "Removing events older than $OlderThan..."

        $toRemove = $script:AllEvents | Where-Object { $_.TimeCreated -lt $OlderThan }
        $removeCount = $toRemove.Count

        foreach ($event in $toRemove) {
            [void]$script:AllEvents.Remove($event)

            # Remove from deduplication cache
            $dedupKey = Get-DeduplicationKey -Event $event
            if ($script:DeduplicationCache.ContainsKey($dedupKey)) {
                $script:DeduplicationCache.Remove($dedupKey)
            }
        }

        Update-EventStatistics

        Write-Verbose "Removed $removeCount old events"
        return @{ success = $true; message = "Removed $removeCount events"; count = $removeCount }
    }
    catch {
        Write-Warning "Failed to remove old events: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PUBLIC FUNCTIONS - FILTERING & STATISTICS
# ============================================================

function Apply-EventFilters {
    <#
    .SYNOPSIS
        Applies filters to the events collection

    .PARAMETER EventType
        Filter by event type: All, Allowed, Blocked, Audit

    .PARAMETER ComputerName
        Filter by computer name

    .PARAMETER Publisher
        Filter by publisher

    .PARAMETER DateRange
        Filter by date range: All, Last Hour, Last 24 Hours, Last 7 Days

    .PARAMETER SearchText
        Filter by search text (matches file path, user, publisher)

    .PARAMETER ShowDuplicates
        Whether to show duplicate events

    .EXAMPLE
        Apply-EventFilters -EventType "Blocked" -DateRange "Last 24 Hours"
        $filtered = Get-EventDisplayItems
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet("All", "Allowed", "Blocked", "Audit")]
        [string]$EventType,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [string]$Publisher,

        [Parameter()]
        [ValidateSet("All", "Last Hour", "Last 24 Hours", "Last 7 Days")]
        [string]$DateRange,

        [Parameter()]
        [string]$SearchText,

        [Parameter()]
        [bool]$ShowDuplicates
    )

    try {
        Write-Verbose "Applying event filters..."

        if ($EventType) { $script:EventFilters.EventType = $EventType }
        if ($ComputerName) { $script:EventFilters.ComputerName = $ComputerName }
        if ($Publisher) { $script:EventFilters.Publisher = $Publisher }
        if ($DateRange) { $script:EventFilters.DateRange = $DateRange }
        if ($null -ne $SearchText) { $script:EventFilters.SearchText = $SearchText }
        if ($null -ne $ShowDuplicates) { $script:EventFilters.ShowDuplicates = $ShowDuplicates }

        Write-Verbose "Filters applied: Type=$($script:EventFilters.EventType), DateRange=$($script:EventFilters.DateRange)"
        return @{ success = $true; message = "Filters applied" }
    }
    catch {
        Write-Warning "Failed to apply filters: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

function Get-EventStatistics {
    <#
    .SYNOPSIS
        Gets statistics about the events collection

    .OUTPUTS
        Hashtable containing event counts and aggregations

    .EXAMPLE
        $stats = Get-EventStatistics
        Write-Host "Total Events: $($stats.TotalEvents)"
    #>
    [CmdletBinding()]
    param()

    try {
        return @{
            TotalEvents = $script:EventStatistics.TotalEvents
            AllowedEvents = $script:EventStatistics.AllowedEvents
            BlockedEvents = $script:EventStatistics.BlockedEvents
            AuditEvents = $script:EventStatistics.AuditEvents
            UniqueApplications = $script:EventStatistics.UniqueApplications
            UniquePublishers = $script:EventStatistics.UniquePublishers
            UniqueComputers = $script:EventStatistics.UniqueComputers
            OldestEvent = $script:EventStatistics.OldestEvent
            NewestEvent = $script:EventStatistics.NewestEvent
        }
    }
    catch {
        Write-Warning "Failed to get event statistics: $($_.Exception.Message)"
        return @{ TotalEvents = 0 }
    }
}

function Get-TopBlockedApplications {
    <#
    .SYNOPSIS
        Gets the most frequently blocked applications

    .PARAMETER TopCount
        Number of top items to return (default: 10)

    .OUTPUTS
        Array of applications with block counts

    .EXAMPLE
        $topBlocked = Get-TopBlockedApplications -TopCount 10
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$TopCount = 10
    )

    try {
        $blockedEvents = $script:AllEvents | Where-Object { $_.EventId -eq 8004 }

        $grouped = $blockedEvents |
            Group-Object -Property FilePath |
            Select-Object @{N='Application'; E={$_.Name}}, Count |
            Sort-Object Count -Descending |
            Select-Object -First $TopCount

        return $grouped
    }
    catch {
        Write-Warning "Failed to get top blocked applications: $($_.Exception.Message)"
        return @()
    }
}

function Export-EventsToCsv {
    <#
    .SYNOPSIS
        Exports events to CSV file

    .PARAMETER FilePath
        Path to export CSV file

    .PARAMETER IncludeFiltered
        Export only filtered events (default: $false, exports all)

    .EXAMPLE
        Export-EventsToCsv -FilePath "C:\Events.csv" -IncludeFiltered $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter()]
        [bool]$IncludeFiltered = $false
    )

    try {
        Write-Verbose "Exporting events to CSV: $FilePath..."

        $events = if ($IncludeFiltered) {
            Get-FilteredEvents
        } else {
            $script:AllEvents.ToArray()
        }

        $events | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8

        Write-Verbose "Exported $($events.Count) events to CSV"
        return @{ success = $true; message = "Exported $($events.Count) events"; count = $events.Count }
    }
    catch {
        Write-Warning "Failed to export events to CSV: $($_.Exception.Message)"
        return @{ success = $false; message = $_.Exception.Message }
    }
}

# ============================================================
# PRIVATE HELPER FUNCTIONS
# ============================================================

function Get-FilteredEvents {
    [CmdletBinding()]
    param()

    $filtered = $script:AllEvents.ToArray()

    # Apply EventType filter
    if ($script:EventFilters.EventType -ne "All") {
        $eventId = switch ($script:EventFilters.EventType) {
            "Allowed" { 8002 }
            "Blocked" { 8004 }
            "Audit"   { 8003 }
        }
        $filtered = $filtered | Where-Object { $_.EventId -eq $eventId }
    }

    # Apply ComputerName filter
    if ($script:EventFilters.ComputerName -ne "All") {
        $filtered = $filtered | Where-Object { $_.ComputerName -eq $script:EventFilters.ComputerName }
    }

    # Apply Publisher filter
    if ($script:EventFilters.Publisher -ne "All") {
        $filtered = $filtered | Where-Object { $_.Publisher -eq $script:EventFilters.Publisher }
    }

    # Apply DateRange filter
    if ($script:EventFilters.DateRange -ne "All") {
        $cutoffDate = switch ($script:EventFilters.DateRange) {
            "Last Hour"      { (Get-Date).AddHours(-1) }
            "Last 24 Hours"  { (Get-Date).AddHours(-24) }
            "Last 7 Days"    { (Get-Date).AddDays(-7) }
        }
        $filtered = $filtered | Where-Object { $_.TimeCreated -ge $cutoffDate }
    }

    # Apply search text filter
    if ($script:EventFilters.SearchText) {
        $searchText = $script:EventFilters.SearchText.ToLower()
        $filtered = $filtered | Where-Object {
            ($_.FilePath -and $_.FilePath.ToLower().Contains($searchText)) -or
            ($_.User -and $_.User.ToLower().Contains($searchText)) -or
            ($_.Publisher -and $_.Publisher.ToLower().Contains($searchText)) -or
            ($_.ComputerName -and $_.ComputerName.ToLower().Contains($searchText))
        }
    }

    return $filtered
}

function Update-EventStatistics {
    [CmdletBinding()]
    param()

    $events = $script:AllEvents.ToArray()

    $script:EventStatistics.TotalEvents = $events.Count
    $script:EventStatistics.AllowedEvents = ($events | Where-Object { $_.EventId -eq 8002 }).Count
    $script:EventStatistics.BlockedEvents = ($events | Where-Object { $_.EventId -eq 8004 }).Count
    $script:EventStatistics.AuditEvents = ($events | Where-Object { $_.EventId -eq 8003 }).Count

    # Unique counts
    $script:EventStatistics.UniqueApplications = ($events | Select-Object -Unique FilePath).Count
    $script:EventStatistics.UniquePublishers = ($events | Where-Object { $_.Publisher } | Select-Object -Unique Publisher).Count
    $script:EventStatistics.UniqueComputers = ($events | Select-Object -Unique ComputerName).Count

    # Date range
    if ($events.Count -gt 0) {
        $script:EventStatistics.OldestEvent = ($events | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        $script:EventStatistics.NewestEvent = ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    } else {
        $script:EventStatistics.OldestEvent = $null
        $script:EventStatistics.NewestEvent = $null
    }
}

function Get-DeduplicationKey {
    param($Event)

    # Create unique key based on event characteristics
    return "$($Event.EventId)_$($Event.FilePath)_$($Event.User)_$($Event.ComputerName)"
}

function Get-DeduplicatedEvents {
    param([array]$Events)

    # Group by deduplication key and return first of each group
    $deduplicated = $Events | Group-Object -Property {
        Get-DeduplicationKey -Event $_
    } | ForEach-Object {
        $first = $_.Group[0]
        $first.DuplicateCount = $_.Count
        $first
    }

    return $deduplicated
}

function Get-EventTypeName {
    param([int]$EventId)

    switch ($EventId) {
        8002 { return "Allowed" }
        8003 { return "Audit" }
        8004 { return "Blocked" }
        8005 { return "Allowed" }
        8006 { return "Audit" }
        8007 { return "Blocked" }
        default { return "Unknown" }
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Initialize-EventsCollection',
    'Get-EventDisplayItems',
    'Get-AllEvents',
    'Add-Events',
    'Clear-Events',
    'Remove-OldEvents',
    'Apply-EventFilters',
    'Get-EventStatistics',
    'Get-TopBlockedApplications',
    'Export-EventsToCsv'
)
