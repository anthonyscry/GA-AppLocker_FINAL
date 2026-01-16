<#
.SYNOPSIS
    Event filtering and search logic

.DESCRIPTION
    Provides filtering functions for AppLocker events with support for event type,
    date range, computer name, and text search filters.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Filter-Events {
    <#
    .SYNOPSIS
        Filters events based on multiple criteria

    .DESCRIPTION
        Applies filtering to AppLocker events using event type, date range,
        computer name, and search text.

    .PARAMETER Events
        Array of event objects to filter

    .PARAMETER EventType
        Filter by event type (All, Allowed, Blocked, Audit)

    .PARAMETER StartDate
        Filter events on or after this date

    .PARAMETER EndDate
        Filter events on or before this date

    .PARAMETER ComputerName
        Filter by computer name (partial match supported)

    .PARAMETER SearchText
        Search text to match against file path, user, publisher, etc.

    .OUTPUTS
        Returns filtered array of events

    .EXAMPLE
        Filter-Events -Events $allEvents -EventType "Blocked" -StartDate (Get-Date).AddDays(-7)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$false)]
        [ValidateSet("All", "Allowed", "Blocked", "Audit")]
        [string]$EventType = "All",

        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = [datetime]::MinValue,

        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = [datetime]::MinValue,

        [Parameter(Mandatory=$false)]
        [string]$ComputerName = "",

        [Parameter(Mandatory=$false)]
        [string]$SearchText = ""
    )

    # Start with all events
    $filteredEvents = @($Events)

    # Filter by event type
    if ($EventType -ne "All") {
        switch ($EventType) {
            "Allowed" {
                $filteredEvents = $filteredEvents | Where-Object { $_.EventID -eq 8002 -or $_.EventType -eq "Allowed" }
            }
            "Blocked" {
                $filteredEvents = $filteredEvents | Where-Object { $_.EventID -eq 8004 -or $_.EventType -eq "Blocked" }
            }
            "Audit" {
                $filteredEvents = $filteredEvents | Where-Object { $_.EventID -eq 8003 -or $_.EventType -eq "Audit" }
            }
        }
    }

    # Filter by date range
    if ($StartDate -gt [datetime]::MinValue) {
        $filteredEvents = $filteredEvents | Where-Object {
            $eventDate = $null
            if ($_.TimeCreated) {
                $eventDate = $_.TimeCreated
            } elseif ($_.Timestamp) {
                $eventDate = $_.Timestamp
            }
            if ($eventDate) {
                $eventDate -ge $StartDate
            } else {
                $false
            }
        }
    }

    if ($EndDate -gt [datetime]::MinValue) {
        $endOfDay = $EndDate.Date.AddDays(1).AddSeconds(-1)
        $filteredEvents = $filteredEvents | Where-Object {
            $eventDate = $null
            if ($_.TimeCreated) {
                $eventDate = $_.TimeCreated
            } elseif ($_.Timestamp) {
                $eventDate = $_.Timestamp
            }
            if ($eventDate) {
                $eventDate -le $endOfDay
            } else {
                $false
            }
        }
    }

    # Filter by computer name
    if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
        $filteredEvents = $filteredEvents | Where-Object {
            $_.ComputerName -like "*$ComputerName*" -or
            $_.computerName -like "*$ComputerName*"
        }
    }

    # Filter by search text
    if (-not [string]::IsNullOrWhiteSpace($SearchText)) {
        $searchLower = $SearchText.ToLower()
        $filteredEvents = $filteredEvents | Where-Object {
            ($_.FilePath -and $_.FilePath.ToLower() -like "*$searchLower*") -or
            ($_.filePath -and $_.filePath.ToLower() -like "*$searchLower*") -or
            ($_.FileName -and $_.FileName.ToLower() -like "*$searchLower*") -or
            ($_.fileName -and $_.fileName.ToLower() -like "*$searchLower*") -or
            ($_.Publisher -and $_.Publisher.ToLower() -like "*$searchLower*") -or
            ($_.publisher -and $_.publisher.ToLower() -like "*$searchLower*") -or
            ($_.UserName -and $_.UserName.ToLower() -like "*$searchLower*") -or
            ($_.userName -and $_.userName.ToLower() -like "*$searchLower*") -or
            ($_.Message -and $_.Message.ToLower() -like "*$searchLower*")
        }
    }

    return $filteredEvents
}

function Get-FilteredEvents {
    <#
    .SYNOPSIS
        Returns filtered event collection using filter object

    .DESCRIPTION
        Applies filters from a hashtable to an event collection.

    .PARAMETER Events
        Array of event objects

    .PARAMETER Filters
        Hashtable of filter criteria with keys: Type, DateFrom, DateTo, Computer, Search

    .OUTPUTS
        Returns filtered array of events

    .EXAMPLE
        $filters = @{ Type = "Blocked"; DateFrom = (Get-Date).AddDays(-7) }
        $filtered = Get-FilteredEvents -Events $allEvents -Filters $filters
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$true)]
        [hashtable]$Filters
    )

    $eventType = if ($Filters.ContainsKey('Type')) { $Filters.Type } else { "All" }
    $dateFrom = if ($Filters.ContainsKey('DateFrom')) { $Filters.DateFrom } else { [datetime]::MinValue }
    $dateTo = if ($Filters.ContainsKey('DateTo')) { $Filters.DateTo } else { [datetime]::MinValue }
    $computer = if ($Filters.ContainsKey('Computer')) { $Filters.Computer } else { "" }
    $search = if ($Filters.ContainsKey('Search')) { $Filters.Search } else { "" }

    return Filter-Events -Events $Events -EventType $eventType -StartDate $dateFrom -EndDate $dateTo -ComputerName $computer -SearchText $search
}

function Get-EventFilterCounts {
    <#
    .SYNOPSIS
        Calculates filter counts for events

    .DESCRIPTION
        Returns counts of events grouped by various filter categories.

    .PARAMETER Events
        Array of event objects

    .OUTPUTS
        Returns hashtable with counts by EventType, Computer, and Date

    .EXAMPLE
        $counts = Get-EventFilterCounts -Events $allEvents
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events
    )

    $counts = @{
        Total = $Events.Count
        ByType = @{
            Allowed = 0
            Blocked = 0
            Audit = 0
        }
        ByComputer = @{}
        ByDate = @{}
    }

    if ($Events.Count -eq 0) {
        return $counts
    }

    foreach ($event in $Events) {
        # Count by type
        switch ($event.EventID) {
            8002 { $counts.ByType.Allowed++ }
            8003 { $counts.ByType.Audit++ }
            8004 { $counts.ByType.Blocked++ }
        }

        # Count by computer
        $computerName = if ($event.ComputerName) { $event.ComputerName } else { $event.computerName }
        if ($computerName) {
            if (-not $counts.ByComputer.ContainsKey($computerName)) {
                $counts.ByComputer[$computerName] = 0
            }
            $counts.ByComputer[$computerName]++
        }

        # Count by date
        $eventDate = if ($event.TimeCreated) { $event.TimeCreated } else { $event.Timestamp }
        if ($eventDate) {
            $dateKey = $eventDate.ToString("yyyy-MM-dd")
            if (-not $counts.ByDate.ContainsKey($dateKey)) {
                $counts.ByDate[$dateKey] = 0
            }
            $counts.ByDate[$dateKey]++
        }
    }

    return $counts
}

function Get-QuickDateFilter {
    <#
    .SYNOPSIS
        Returns date range for quick filter presets

    .DESCRIPTION
        Generates start and end dates for common filter presets like "Last Hour", "Today", etc.

    .PARAMETER Preset
        The preset filter name (LastHour, Today, Last7Days, Last30Days)

    .OUTPUTS
        Returns hashtable with StartDate and EndDate

    .EXAMPLE
        $range = Get-QuickDateFilter -Preset "Last7Days"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("LastHour", "Today", "Last7Days", "Last30Days")]
        [string]$Preset
    )

    $now = Get-Date
    $range = @{
        StartDate = $now
        EndDate = $now
    }

    switch ($Preset) {
        "LastHour" {
            $range.StartDate = $now.AddHours(-1)
            $range.EndDate = $now
        }
        "Today" {
            $range.StartDate = $now.Date
            $range.EndDate = $now
        }
        "Last7Days" {
            $range.StartDate = $now.AddDays(-7)
            $range.EndDate = $now
        }
        "Last30Days" {
            $range.StartDate = $now.AddDays(-30)
            $range.EndDate = $now
        }
    }

    return $range
}

function Sort-EventsByProperty {
    <#
    .SYNOPSIS
        Sorts events by specified property

    .DESCRIPTION
        Sorts event collection by a given property in ascending or descending order.

    .PARAMETER Events
        Array of event objects

    .PARAMETER Property
        Property name to sort by (TimeCreated, EventType, ComputerName, etc.)

    .PARAMETER Descending
        Sort in descending order (default: ascending)

    .OUTPUTS
        Returns sorted array of events

    .EXAMPLE
        $sorted = Sort-EventsByProperty -Events $allEvents -Property "TimeCreated" -Descending
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$true)]
        [string]$Property,

        [Parameter(Mandatory=$false)]
        [switch]$Descending
    )

    if ($Descending) {
        return $Events | Sort-Object -Property $Property -Descending
    } else {
        return $Events | Sort-Object -Property $Property
    }
}

function Group-EventsByProperty {
    <#
    .SYNOPSIS
        Groups events by specified property

    .DESCRIPTION
        Groups event collection by a property for analysis and reporting.

    .PARAMETER Events
        Array of event objects

    .PARAMETER Property
        Property name to group by

    .OUTPUTS
        Returns grouped event collection

    .EXAMPLE
        $grouped = Group-EventsByProperty -Events $allEvents -Property "ComputerName"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$true)]
        [string]$Property
    )

    return $Events | Group-Object -Property $Property
}

Export-ModuleMember -Function Filter-Events, Get-FilteredEvents, Get-EventFilterCounts, Get-QuickDateFilter, Sort-EventsByProperty, Group-EventsByProperty
