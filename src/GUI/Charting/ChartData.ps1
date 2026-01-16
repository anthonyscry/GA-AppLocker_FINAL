<#
.SYNOPSIS
    Chart data preparation and processing

.DESCRIPTION
    Provides functions for preparing, normalizing, and aggregating data for chart rendering.

.NOTES
    Author: GA-AppLocker Team
    Version: 1.2.5
#>

function Prepare-EventChartData {
    <#
    .SYNOPSIS
        Aggregates event data for chart visualization

    .DESCRIPTION
        Processes AppLocker event data and prepares it for chart rendering.
        Groups events by type and calculates totals.

    .PARAMETER Events
        Array of AppLocker event objects

    .OUTPUTS
        Returns hashtable with event counts by type

    .EXAMPLE
        $chartData = Prepare-EventChartData -Events $allEvents
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events
    )

    $chartData = @{
        Allowed = 0
        Audited = 0
        Blocked = 0
        Total = 0
    }

    if ($null -eq $Events -or $Events.Count -eq 0) {
        return $chartData
    }

    foreach ($event in $Events) {
        $chartData.Total++

        switch ($event.EventID) {
            8002 { $chartData.Allowed++ }
            8003 { $chartData.Audited++ }
            8004 { $chartData.Blocked++ }
        }
    }

    return $chartData
}

function Get-ChartColors {
    <#
    .SYNOPSIS
        Returns color palette for charts

    .DESCRIPTION
        Provides color schemes for different chart types and themes.

    .PARAMETER ColorScheme
        The color scheme to use (GitHubDark, Light, HighContrast)

    .OUTPUTS
        Returns hashtable of color mappings

    .EXAMPLE
        $colors = Get-ChartColors -ColorScheme "GitHubDark"
    #>
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("GitHubDark", "Light", "HighContrast")]
        [string]$ColorScheme = "GitHubDark"
    )

    switch ($ColorScheme) {
        "GitHubDark" {
            return @{
                # Event colors
                Allowed = "#3FB950"  # Green
                Audited = "#D29922"  # Orange/Yellow
                Blocked = "#F85149"  # Red

                # Chart elements
                Primary = "#58A6FF"  # Blue
                Secondary = "#8B949E"  # Gray
                Background = "#0D1117"  # Dark gray
                Border = "#30363D"  # Medium gray
                Text = "#E6EDF3"  # Light gray

                # Status colors
                Success = "#3FB950"
                Warning = "#D29922"
                Error = "#F85149"
                Info = "#58A6FF"

                # Publisher colors
                Microsoft = "#0078D4"
                Adobe = "#FF0000"
                Google = "#4285F4"
                Unknown = "#8B949E"
            }
        }
        "Light" {
            return @{
                Allowed = "#2DA44E"
                Audited = "#BF8700"
                Blocked = "#CF222E"

                Primary = "#0969DA"
                Secondary = "#57606A"
                Background = "#FFFFFF"
                Border = "#D0D7DE"
                Text = "#1F2328"

                Success = "#2DA44E"
                Warning = "#BF8700"
                Error = "#CF222E"
                Info = "#0969DA"

                Microsoft = "#0078D4"
                Adobe = "#FF0000"
                Google = "#4285F4"
                Unknown = "#57606A"
            }
        }
        "HighContrast" {
            return @{
                Allowed = "#00FF00"
                Audited = "#FFFF00"
                Blocked = "#FF0000"

                Primary = "#00FFFF"
                Secondary = "#FFFFFF"
                Background = "#000000"
                Border = "#FFFFFF"
                Text = "#FFFFFF"

                Success = "#00FF00"
                Warning = "#FFFF00"
                Error = "#FF0000"
                Info = "#00FFFF"

                Microsoft = "#00FFFF"
                Adobe = "#FF00FF"
                Google = "#00FFFF"
                Unknown = "#FFFFFF"
            }
        }
    }
}

function Normalize-ChartData {
    <#
    .SYNOPSIS
        Normalizes data for charting

    .DESCRIPTION
        Scales data values to fit within a specified range for visualization.

    .PARAMETER Data
        Array of numeric values to normalize

    .PARAMETER MaxValue
        Maximum value for normalization (default: 100)

    .PARAMETER MinValue
        Minimum value for normalization (default: 0)

    .OUTPUTS
        Returns array of normalized values

    .EXAMPLE
        $normalized = Normalize-ChartData -Data @(10, 50, 100, 200) -MaxValue 100
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,

        [Parameter(Mandatory=$false)]
        [int]$MaxValue = 100,

        [Parameter(Mandatory=$false)]
        [int]$MinValue = 0
    )

    if ($null -eq $Data -or $Data.Count -eq 0) {
        return @()
    }

    $dataMin = ($Data | Measure-Object -Minimum).Minimum
    $dataMax = ($Data | Measure-Object -Maximum).Maximum

    if ($dataMax -eq $dataMin) {
        # All values are the same
        return @($MaxValue) * $Data.Count
    }

    $normalized = @()
    foreach ($value in $Data) {
        $normalizedValue = $MinValue + (($value - $dataMin) / ($dataMax - $dataMin)) * ($MaxValue - $MinValue)
        $normalized += [Math]::Round($normalizedValue, 2)
    }

    return $normalized
}

function Get-PolicyHealthScore {
    <#
    .SYNOPSIS
        Calculates policy health score

    .DESCRIPTION
        Calculates a score (0-100) representing the completeness and quality of AppLocker policies.

    .PARAMETER Rules
        Array of AppLocker rule objects

    .OUTPUTS
        Returns integer score from 0-100

    .EXAMPLE
        $score = Get-PolicyHealthScore -Rules $allRules
    #>
    param(
        [Parameter(Mandatory=$false)]
        [array]$Rules = @()
    )

    $score = 0

    # Base score: rules exist
    if ($Rules.Count -gt 0) {
        $score += 20
    }

    # Rule diversity score (different types)
    $ruleTypes = $Rules | Select-Object -ExpandProperty type -Unique
    if ($ruleTypes -contains "Publisher") { $score += 20 }
    if ($ruleTypes -contains "Hash") { $score += 10 }
    if ($ruleTypes -contains "Path") { $score += 5 }

    # Rule count score
    if ($Rules.Count -ge 10) { $score += 10 }
    if ($Rules.Count -ge 50) { $score += 10 }
    if ($Rules.Count -ge 100) { $score += 10 }

    # Deny rules present (security best practice)
    $denyRules = $Rules | Where-Object { $_.action -eq "Deny" }
    if ($denyRules.Count -gt 0) { $score += 15 }

    # Group coverage (multiple groups configured)
    $groups = $Rules | Select-Object -ExpandProperty userOrGroupSid -Unique
    if ($groups.Count -ge 2) { $score += 5 }
    if ($groups.Count -ge 4) { $score += 5 }

    # Cap at 100
    return [Math]::Min(100, $score)
}

function Get-EventSummary {
    <#
    .SYNOPSIS
        Generates event summary statistics

    .DESCRIPTION
        Creates a comprehensive summary of AppLocker events with counts and breakdowns.

    .PARAMETER Events
        Array of AppLocker event objects

    .OUTPUTS
        Returns hashtable with summary statistics

    .EXAMPLE
        $summary = Get-EventSummary -Events $allEvents
    #>
    param(
        [Parameter(Mandatory=$false)]
        [array]$Events = @()
    )

    $summary = @{
        events = @{
            total = 0
            allowed = 0
            audited = 0
            blocked = 0
        }
        computers = @()
        publishers = @()
        dateRange = @{
            earliest = $null
            latest = $null
        }
        policyHealth = @{
            score = 0
        }
    }

    if ($null -eq $Events -or $Events.Count -eq 0) {
        return $summary
    }

    # Process events
    $computerSet = @{}
    $publisherSet = @{}
    $dates = @()

    foreach ($event in $Events) {
        $summary.events.total++

        switch ($event.EventID) {
            8002 { $summary.events.allowed++ }
            8003 { $summary.events.audited++ }
            8004 { $summary.events.blocked++ }
        }

        # Track computers
        if ($event.ComputerName) {
            $computerSet[$event.ComputerName] = $true
        }

        # Track publishers
        if ($event.Publisher) {
            $publisherSet[$event.Publisher] = $true
        }

        # Track dates
        if ($event.TimeCreated) {
            $dates += $event.TimeCreated
        }
    }

    $summary.computers = @($computerSet.Keys)
    $summary.publishers = @($publisherSet.Keys)

    if ($dates.Count -gt 0) {
        $summary.dateRange.earliest = ($dates | Measure-Object -Minimum).Minimum
        $summary.dateRange.latest = ($dates | Measure-Object -Maximum).Maximum
    }

    return $summary
}

function Format-ChartLegend {
    <#
    .SYNOPSIS
        Formats legend text for charts

    .DESCRIPTION
        Creates formatted legend text showing data breakdown.

    .PARAMETER Data
        Hashtable of data values

    .PARAMETER Colors
        Hashtable of colors

    .OUTPUTS
        Returns formatted legend string

    .EXAMPLE
        $legend = Format-ChartLegend -Data @{Allowed=100; Blocked=20} -Colors $colors
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Data,

        [Parameter(Mandatory=$false)]
        [hashtable]$Colors = @{}
    )

    $total = ($Data.Values | Measure-Object -Sum).Sum
    if ($total -eq 0) { $total = 1 }

    $legend = ""
    foreach ($key in $Data.Keys | Sort-Object) {
        $value = $Data[$key]
        $percentage = [Math]::Round(($value / $total) * 100, 1)
        $legend += "$key`: $value ($percentage%)`n"
    }

    return $legend.TrimEnd()
}

Export-ModuleMember -Function Prepare-EventChartData, Get-ChartColors, Normalize-ChartData, Get-PolicyHealthScore, Get-EventSummary, Format-ChartLegend
