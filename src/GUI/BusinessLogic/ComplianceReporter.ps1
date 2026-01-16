<#
.SYNOPSIS
    AppLocker compliance reporting business logic

.DESCRIPTION
    Core functions for generating compliance reports, executive summaries, technical reports,
    audit trails, and scheduled reports. Provides export capabilities to HTML, CSV, and text formats.

.NOTES
    Module Name: ComplianceReporter
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: EventProcessor module (for Get-AppLockerEventsForReport)

.EXAMPLE
    Import-Module .\ComplianceReporter.ps1

    # Generate executive summary
    $startDate = (Get-Date).AddDays(-30)
    $endDate = Get-Date
    $report = New-ComplianceReport -ReportType "Executive" -StartDate $startDate -EndDate $endDate

    if ($report.success) {
        Write-Host "Report: $($report.data.ReportTitle)"
        Write-Host "Risk Score: $($report.data.RiskScore)"
    }

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level variable to store current report data
$script:CurrentReportData = $null

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function New-ComplianceReport {
    <#
    .SYNOPSIS
        Generates comprehensive compliance report

    .DESCRIPTION
        Main function to generate compliance reports based on specified type and date range.
        Supports Executive, Technical, Audit, and Comparison report types.

    .PARAMETER ReportType
        Type of report: Executive, Technical, Audit, or Comparison

    .PARAMETER StartDate
        Start date for report period

    .PARAMETER EndDate
        End date for report period

    .PARAMETER TargetSystem
        Target system: All or Local (default: All)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - data: Report data object
        - error: Error message (if failure)

    .EXAMPLE
        $report = New-ComplianceReport -ReportType "Executive" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
        if ($report.success) {
            Write-Host "Generated report: $($report.data.ReportTitle)"
        }

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Executive report generation
        $startDate = (Get-Date).AddDays(-7)
        $endDate = Get-Date
        $report = New-ComplianceReport -ReportType "Executive" -StartDate $startDate -EndDate $endDate
        Assert ($report.success -eq $true)
        Assert ($report.data.ReportType -eq "Executive")
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Executive", "Technical", "Audit", "Comparison")]
        [string]$ReportType,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Local")]
        [string]$TargetSystem = "All"
    )

    try {
        Write-Verbose "Generating $ReportType report from $StartDate to $EndDate"

        # Base report metadata
        $reportData = @{
            ReportType = $ReportType
            StartDate = $StartDate
            EndDate = $EndDate
            TargetSystem = $TargetSystem
            GeneratedAt = Get-Date
            GeneratedBy = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
        }

        # Generate type-specific report data
        switch ($ReportType) {
            "Executive" {
                $typeData = Get-ExecutiveSummaryReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
                $reportData += $typeData
            }
            "Technical" {
                $typeData = Get-DetailedTechnicalReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
                $reportData += $typeData
            }
            "Audit" {
                $typeData = Get-AuditTrailReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
                $reportData += $typeData
            }
            "Comparison" {
                $typeData = Get-PolicyComparisonReport -StartDate $StartDate -EndDate $EndDate -TargetSystem $TargetSystem
                $reportData += $typeData
            }
        }

        # Store for export functions
        $script:CurrentReportData = $reportData

        Write-Verbose "Report generation complete: $($reportData.ReportTitle)"

        return @{
            success = $true
            data = $reportData
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to generate compliance report: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Get-ExecutiveSummaryReport {
    <#
    .SYNOPSIS
        Generates executive summary report with high-level metrics

    .DESCRIPTION
        Creates a business-focused report with compliance percentage, risk score,
        top violations, and policy health metrics.

    .PARAMETER StartDate
        Start date for analysis

    .PARAMETER EndDate
        End date for analysis

    .PARAMETER TargetSystem
        Target system scope

    .OUTPUTS
        Hashtable with executive summary data

    .NOTES
        Internal function called by New-ComplianceReport
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    Write-Verbose "Generating Executive Summary Report"

    # Get AppLocker events for the period
    $events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $EndDate

    # Calculate compliance metrics
    $totalEvents = $events.Count
    $allowedEvents = ($events | Where-Object { $_.EventType -eq "Allowed" }).Count
    $blockedEvents = ($events | Where-Object { $_.EventType -eq "Blocked" }).Count
    $auditedEvents = ($events | Where-Object { $_.EventType -eq "Audited" }).Count

    # Calculate compliance percentage
    $compliancePercentage = if ($totalEvents -gt 0) {
        [math]::Round((($allowedEvents + $auditedEvents) / $totalEvents) * 100, 2)
    }
    else {
        100
    }

    # Calculate risk score (0-100, lower is better)
    $riskScore = if ($totalEvents -gt 0) {
        [math]::Min(100, [math]::Round(($blockedEvents / $totalEvents) * 100, 2))
    }
    else {
        0
    }

    # Determine risk level
    $riskLevel = switch ($riskScore) {
        { $_ -lt 10 } { "Low" }
        { $_ -lt 30 } { "Medium" }
        { $_ -lt 50 } { "High" }
        default { "Critical" }
    }

    # Get top violating applications
    $topViolatingApps = $events |
        Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
        Group-Object -Property FileName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                Application = $_.Name
                ViolationCount = $_.Count
                Percentage = if ($totalEvents -gt 0) {
                    [math]::Round(($_.Count / $totalEvents) * 100, 2)
                }
                else { 0 }
            }
        }

    # Get top violating users
    $topViolatingUsers = $events |
        Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
        Group-Object -Property UserSid |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [PSCustomObject]@{
                User = $_.Name
                ViolationCount = $_.Count
            }
        }

    # Get policy health
    $policyHealth = Get-PolicyHealthScore

    # Calculate trend data
    $trendData = Get-ComplianceTrend -StartDate $StartDate -EndDate $EndDate

    return @{
        ReportTitle = "Executive Summary Report"
        ReportSummary = "High-level overview of AppLocker compliance status"
        OverallCompliance = $compliancePercentage
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        TotalEvents = $totalEvents
        AllowedEvents = $allowedEvents
        BlockedEvents = $blockedEvents
        AuditedEvents = $auditedEvents
        TopViolatingApps = $topViolatingApps
        TopViolatingUsers = $topViolatingUsers
        PolicyHealth = $policyHealth
        TrendData = $trendData
        PolicyCoverage = @{
            ExeCoverage = if ($policyHealth.hasExe) { "Yes" } else { "No" }
            MsiCoverage = if ($policyHealth.hasMsi) { "Yes" } else { "No" }
            ScriptCoverage = if ($policyHealth.hasScript) { "Yes" } else { "No" }
            DllCoverage = if ($policyHealth.hasDll) { "Yes" } else { "No" }
        }
    }
}

function Get-DetailedTechnicalReport {
    <#
    .SYNOPSIS
        Generates detailed technical report with full event logs

    .DESCRIPTION
        Creates a comprehensive technical report with event breakdowns,
        policy rules, file paths, publishers, and violation details.

    .PARAMETER StartDate
        Start date for analysis

    .PARAMETER EndDate
        End date for analysis

    .PARAMETER TargetSystem
        Target system scope

    .OUTPUTS
        Hashtable with detailed technical data

    .NOTES
        Internal function called by New-ComplianceReport
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    Write-Verbose "Generating Detailed Technical Report"

    # Get all events
    $events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $EndDate

    # Event statistics
    $eventsByType = $events |
        Group-Object -Property EventType |
        ForEach-Object {
            [PSCustomObject]@{
                Type = $_.Name
                Count = $_.Count
                Percentage = if ($events.Count -gt 0) {
                    [math]::Round(($_.Count / $events.Count) * 100, 2)
                }
                else { 0 }
            }
        }

    # Events by day
    $eventsByDay = $events |
        Group-Object -Property { $_.TimeCreated.ToString("yyyy-MM-dd") } |
        Sort-Object -Property Name |
        ForEach-Object {
            [PSCustomObject]@{
                Date = $_.Name
                Count = $_.Count
            }
        }

    # Events by hour
    $eventsByHour = $events |
        Group-Object -Property { $_.TimeCreated.Hour } |
        Sort-Object -Property Name |
        ForEach-Object {
            [PSCustomObject]@{
                Hour = $_.Name
                Count = $_.Count
            }
        }

    # Top file paths
    $topFilePaths = $events |
        Where-Object { $_.FilePath -and $_.FilePath -ne "Unknown" } |
        Group-Object -Property FilePath |
        Sort-Object -Property Count -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            $eventTypes = $_.Group | Group-Object -Property EventType
            [PSCustomObject]@{
                FilePath = $_.Name
                Count = $_.Count
                PrimaryEventType = ($eventTypes | Sort-Object -Property Count -Descending | Select-Object -First 1).Name
            }
        }

    # Top publishers
    $topPublishers = $events |
        Where-Object { $_.Publisher -and $_.Publisher -ne "Unknown" } |
        Group-Object -Property Publisher |
        Sort-Object -Property Count -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            [PSCustomObject]@{
                Publisher = $_.Name
                Count = $_.Count
            }
        }

    # Get policy details
    $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    $policyRules = @()

    if ($policy) {
        foreach ($collection in $policy.RuleCollections) {
            foreach ($rule in $collection) {
                $policyRules += [PSCustomObject]@{
                    RuleType = $collection.RuleCollectionType
                    RuleName = $rule.Name
                    Action = $rule.Action
                    UserOrGroup = if ($rule.UserOrGroupSid) { $rule.UserOrGroupSid } else { "N/A" }
                    Condition = if ($rule.Conditions) { $rule.Conditions.GetType().Name } else { "N/A" }
                }
            }
        }
    }

    # Recent violations (last 50)
    $recentViolations = $events |
        Where-Object { $_.EventType -eq "Blocked" -or $_.EventType -eq "Audited" } |
        Sort-Object -Property TimeCreated -Descending |
        Select-Object -First 50

    return @{
        ReportTitle = "Detailed Technical Report"
        ReportSummary = "Full event logs, rule analysis, and violation details"
        TotalEvents = $events.Count
        EventsByType = $eventsByType
        EventsByDay = $eventsByDay
        EventsByHour = $eventsByHour
        TopFilePaths = $topFilePaths
        TopPublishers = $topPublishers
        PolicyRules = $policyRules
        RecentViolations = $recentViolations
        EventDetails = $events
    }
}

function Get-AuditTrailReport {
    <#
    .SYNOPSIS
        Generates audit trail report with admin actions

    .DESCRIPTION
        Creates a report of all administrative actions and policy changes
        from Windows Security and AppLocker logs.

    .PARAMETER StartDate
        Start date for analysis

    .PARAMETER EndDate
        End date for analysis

    .PARAMETER TargetSystem
        Target system scope

    .OUTPUTS
        Hashtable with audit trail data

    .NOTES
        Internal function called by New-ComplianceReport
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    Write-Verbose "Generating Audit Trail Report"

    $auditEvents = @()

    # Get Security log events for policy changes
    try {
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4688, 4689, 5136, 5137, 5141
            StartTime = $StartDate
            EndTime = $EndDate
        } -ErrorAction SilentlyContinue

        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                try {
                    $eventXml = [xml]$event.ToXml()

                    $eventType = switch ($event.Id) {
                        4688 { "Process Created" }
                        4689 { "Process Terminated" }
                        5136 { "Object Created" }
                        5137 { "Object Deleted" }
                        5141 { "Object Modified" }
                        default { "Other" }
                    }

                    $userSid = "Unknown"
                    if ($eventXml.Event.EventData.Data[1] -and $eventXml.Event.EventData.Data[1].'#text') {
                        $userSid = $eventXml.Event.EventData.Data[1].'#text'
                    }

                    $auditEvents += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventId = $event.Id
                        EventType = $eventType
                        UserSid = $userSid
                        Message = $event.Message
                    }
                }
                catch {
                    # Skip events that fail to parse
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve security events: $($_.Exception.Message)"
    }

    # Group audit events by date
    $eventsByDate = $auditEvents |
        Group-Object -Property { $_.TimeCreated.ToString("yyyy-MM-dd") } |
        Sort-Object -Property Name |
        ForEach-Object {
            [PSCustomObject]@{
                Date = $_.Name
                EventCount = $_.Count
            }
        }

    # Events by user
    $eventsByUser = $auditEvents |
        Where-Object { $_.UserSid } |
        Group-Object -Property UserSid |
        Sort-Object -Property Count -Descending |
        Select-Object -First 20 |
        ForEach-Object {
            [PSCustomObject]@{
                User = $_.Name
                ActionCount = $_.Count
            }
        }

    # Recent audit events (last 100)
    $recentAuditEvents = $auditEvents |
        Sort-Object -Property TimeCreated -Descending |
        Select-Object -First 100

    return @{
        ReportTitle = "Audit Trail Report"
        ReportSummary = "Complete history of admin actions and policy changes"
        TotalAuditEvents = $auditEvents.Count
        EventsByDate = $eventsByDate
        EventsByUser = $eventsByUser
        RecentAuditEvents = $recentAuditEvents
        AuditTrail = $auditEvents
    }
}

function Get-PolicyComparisonReport {
    <#
    .SYNOPSIS
        Generates policy comparison report across time periods

    .DESCRIPTION
        Compares AppLocker events and policy effectiveness between two time periods
        within the specified date range.

    .PARAMETER StartDate
        Start date for comparison

    .PARAMETER EndDate
        End date for comparison

    .PARAMETER TargetSystem
        Target system scope

    .OUTPUTS
        Hashtable with comparison data

    .NOTES
        Internal function called by New-ComplianceReport
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$TargetSystem
    )

    Write-Verbose "Generating Policy Comparison Report"

    # Get current policy
    $currentPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

    # Calculate comparison periods (split date range in half)
    $daysDiff = ($EndDate - $StartDate).Days
    $midPoint = $StartDate.AddDays($daysDiff / 2)

    # Get events for period 1 (first half)
    $period1Events = Get-AppLockerEventsForReport -StartDate $StartDate -EndDate $midPoint

    # Get events for period 2 (second half)
    $period2Events = Get-AppLockerEventsForReport -StartDate $midPoint.AddDays(1) -EndDate $EndDate

    # Compare metrics
    $period1Stats = @{
        TotalEvents = $period1Events.Count
        BlockedEvents = ($period1Events | Where-Object { $_.EventType -eq "Blocked" }).Count
        AuditedEvents = ($period1Events | Where-Object { $_.EventType -eq "Audited" }).Count
        AllowedEvents = ($period1Events | Where-Object { $_.EventType -eq "Allowed" }).Count
    }

    $period2Stats = @{
        TotalEvents = $period2Events.Count
        BlockedEvents = ($period2Events | Where-Object { $_.EventType -eq "Blocked" }).Count
        AuditedEvents = ($period2Events | Where-Object { $_.EventType -eq "Audited" }).Count
        AllowedEvents = ($period2Events | Where-Object { $_.EventType -eq "Allowed" }).Count
    }

    # Calculate changes
    $totalEventsChange = if ($period1Stats.TotalEvents -gt 0) {
        [math]::Round((($period2Stats.TotalEvents - $period1Stats.TotalEvents) / $period1Stats.TotalEvents) * 100, 2)
    }
    else { 0 }

    $blockedEventsChange = if ($period1Stats.BlockedEvents -gt 0) {
        [math]::Round((($period2Stats.BlockedEvents - $period1Stats.BlockedEvents) / $period1Stats.BlockedEvents) * 100, 2)
    }
    else { 0 }

    # Top applications in each period
    $period1TopApps = $period1Events |
        Group-Object -Property FileName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10

    $period2TopApps = $period2Events |
        Group-Object -Property FileName |
        Sort-Object -Property Count -Descending |
        Select-Object -First 10

    # Compare top applications
    $appComparison = @()
    $allApps = ($period1TopApps.Name + $period2TopApps.Name) | Select-Object -Unique

    foreach ($app in $allApps) {
        $p1Count = ($period1TopApps | Where-Object { $_.Name -eq $app }).Count
        $p2Count = ($period2TopApps | Where-Object { $_.Name -eq $app }).Count

        if ($null -eq $p1Count) { $p1Count = 0 }
        if ($null -eq $p2Count) { $p2Count = 0 }

        $appComparison += [PSCustomObject]@{
            Application = $app
            Period1Count = $p1Count
            Period2Count = $p2Count
            Change = $p2Count - $p1Count
        }
    }

    # Count current policy rules
    $currentRuleCount = 0
    if ($currentPolicy) {
        foreach ($collection in $currentPolicy.RuleCollections) {
            $currentRuleCount += if ($collection.Count) { $collection.Count } else { 0 }
        }
    }

    return @{
        ReportTitle = "Policy Comparison Report"
        ReportSummary = "Compare policies and events across different time periods"
        Period1 = @{
            StartDate = $StartDate
            EndDate = $midPoint
            Stats = $period1Stats
        }
        Period2 = @{
            StartDate = $midPoint.AddDays(1)
            EndDate = $EndDate
            Stats = $period2Stats
        }
        TotalEventsChange = $totalEventsChange
        BlockedEventsChange = $blockedEventsChange
        Period1TopApps = $period1TopApps
        Period2TopApps = $period2TopApps
        AppComparison = $appComparison
        CurrentPolicyRules = $currentRuleCount
    }
}

function Get-ComplianceTrend {
    <#
    .SYNOPSIS
        Calculates compliance trend over 30/60/90 day periods

    .DESCRIPTION
        Analyzes compliance trends over multiple time periods within the date range.

    .PARAMETER StartDate
        Start date for trend analysis

    .PARAMETER EndDate
        End date for trend analysis

    .OUTPUTS
        Array of trend data objects

    .NOTES
        Internal helper function
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartDate,
        [datetime]$EndDate
    )

    $trendData = @()

    try {
        # Calculate 30-day trends
        $period30Days = $EndDate.AddDays(-30)
        if ($period30Days -lt $StartDate) { $period30Days = $StartDate }

        $events30Days = Get-AppLockerEventsForReport -StartDate $period30Days -EndDate $EndDate
        $compliance30Days = if ($events30Days.Count -gt 0) {
            $allowed = ($events30Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events30Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events30Days.Count) * 100, 2)
        }
        else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "30 Days"
            Compliance = $compliance30Days
            EventCount = $events30Days.Count
        }

        # Calculate 60-day trends
        $period60Days = $EndDate.AddDays(-60)
        if ($period60Days -lt $StartDate) { $period60Days = $StartDate }

        $events60Days = Get-AppLockerEventsForReport -StartDate $period60Days -EndDate $EndDate
        $compliance60Days = if ($events60Days.Count -gt 0) {
            $allowed = ($events60Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events60Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events60Days.Count) * 100, 2)
        }
        else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "60 Days"
            Compliance = $compliance60Days
            EventCount = $events60Days.Count
        }

        # Calculate 90-day trends
        $period90Days = $EndDate.AddDays(-90)
        if ($period90Days -lt $StartDate) { $period90Days = $StartDate }

        $events90Days = Get-AppLockerEventsForReport -StartDate $period90Days -EndDate $EndDate
        $compliance90Days = if ($events90Days.Count -gt 0) {
            $allowed = ($events90Days | Where-Object { $_.EventType -eq "Allowed" }).Count
            $audited = ($events90Days | Where-Object { $_.EventType -eq "Audited" }).Count
            [math]::Round((($allowed + $audited) / $events90Days.Count) * 100, 2)
        }
        else { 100 }

        $trendData += [PSCustomObject]@{
            Period = "90 Days"
            Compliance = $compliance90Days
            EventCount = $events90Days.Count
        }
    }
    catch {
        Write-Verbose "Error calculating compliance trends: $($_.Exception.Message)"
    }

    return $trendData
}

function Export-ReportToPdf {
    <#
    .SYNOPSIS
        Exports report to PDF-compatible text format

    .DESCRIPTION
        Converts report data to a text file that can be printed to PDF.
        For full PDF support, additional libraries like iText7 would be required.

    .PARAMETER ReportData
        Report data object from New-ComplianceReport

    .PARAMETER OutputPath
        Path for output file

    .OUTPUTS
        Hashtable with export result

    .EXAMPLE
        $report = New-ComplianceReport -ReportType "Executive" -StartDate $start -EndDate $end
        $result = Export-ReportToPdf -ReportData $report.data -OutputPath "C:\Reports\executive.txt"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $ReportData,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    )

    try {
        Write-Verbose "Exporting report to PDF-compatible format: $OutputPath"

        # Generate report text
        $reportText = Format-ReportAsText -ReportData $ReportData

        # Create directory if needed
        $directory = Split-Path -Path $OutputPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        # Save to file
        $reportText | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        Write-Verbose "Report exported successfully: $OutputPath"

        return @{
            success = $true
            outputPath = $OutputPath
            message = "Report exported successfully. Note: This is a text export. For PDF conversion, use a PDF printer or additional libraries."
        }
    }
    catch {
        return @{
            success = $false
            error = "PDF export failed: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Export-ReportToHtml {
    <#
    .SYNOPSIS
        Exports report to HTML format with embedded CSS

    .DESCRIPTION
        Converts report data to a styled HTML file for easy viewing in browsers.

    .PARAMETER ReportData
        Report data object from New-ComplianceReport

    .PARAMETER OutputPath
        Path for output HTML file

    .OUTPUTS
        Hashtable with export result

    .EXAMPLE
        $report = New-ComplianceReport -ReportType "Technical" -StartDate $start -EndDate $end
        $result = Export-ReportToHtml -ReportData $report.data -OutputPath "C:\Reports\technical.html"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $ReportData,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    )

    try {
        Write-Verbose "Exporting report to HTML: $OutputPath"

        $html = Format-ReportAsHtml -ReportData $ReportData

        # Create directory if needed
        $directory = Split-Path -Path $OutputPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        Write-Verbose "HTML report exported successfully: $OutputPath"

        return @{
            success = $true
            outputPath = $OutputPath
            message = "HTML report exported successfully"
        }
    }
    catch {
        return @{
            success = $false
            error = "HTML export failed: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Export-ReportToCsv {
    <#
    .SYNOPSIS
        Exports report data to CSV format

    .DESCRIPTION
        Converts the primary data from the report to CSV for data analysis.

    .PARAMETER ReportData
        Report data object from New-ComplianceReport

    .PARAMETER OutputPath
        Path for output CSV file

    .OUTPUTS
        Hashtable with export result

    .EXAMPLE
        $report = New-ComplianceReport -ReportType "Audit" -StartDate $start -EndDate $end
        $result = Export-ReportToCsv -ReportData $report.data -OutputPath "C:\Reports\audit.csv"
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $ReportData,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$env:TEMP\GA-AppLocker-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    )

    try {
        Write-Verbose "Exporting report data to CSV: $OutputPath"

        # Create directory if needed
        $directory = Split-Path -Path $OutputPath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        # Export based on report type
        switch ($ReportData.ReportType) {
            "Executive" {
                # Export top violating applications
                if ($ReportData.TopViolatingApps) {
                    $ReportData.TopViolatingApps | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                }
            }
            "Technical" {
                # Export event details
                if ($ReportData.EventDetails) {
                    $ReportData.EventDetails | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                }
            }
            "Audit" {
                # Export audit trail
                if ($ReportData.AuditTrail) {
                    $ReportData.AuditTrail | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                }
            }
            "Comparison" {
                # Export app comparison
                if ($ReportData.AppComparison) {
                    $ReportData.AppComparison | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                }
            }
        }

        Write-Verbose "CSV report exported successfully: $OutputPath"

        return @{
            success = $true
            outputPath = $OutputPath
            message = "CSV report exported successfully"
        }
    }
    catch {
        return @{
            success = $false
            error = "CSV export failed: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Format-ReportAsText {
    <#
    .SYNOPSIS
        Formats report data as plain text

    .PARAMETER ReportData
        Report data object

    .OUTPUTS
        String containing formatted report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ReportData
    )

    $text = "=" * 80 + "`n"
    $text += "$($ReportData.ReportTitle)`n"
    $text += "=" * 80 + "`n`n"
    $text += "Generated: $($ReportData.GeneratedAt)`n"
    $text += "Generated By: $($ReportData.GeneratedBy)`n"
    $text += "Computer: $($ReportData.ComputerName)`n"
    $text += "Period: $($ReportData.StartDate.ToString('yyyy-MM-dd')) to $($ReportData.EndDate.ToString('yyyy-MM-dd'))`n"
    $text += "`n$($ReportData.ReportSummary)`n"
    $text += "-" * 80 + "`n`n"

    # Add type-specific content
    switch ($ReportData.ReportType) {
        "Executive" {
            $text += "EXECUTIVE SUMMARY`n"
            $text += "-" * 80 + "`n"
            $text += "Overall Compliance: $($ReportData.OverallCompliance)%`n"
            $text += "Risk Score: $($ReportData.RiskScore) ($($ReportData.RiskLevel))`n"
            $text += "Total Events: $($ReportData.TotalEvents)`n"
            $text += "  - Allowed: $($ReportData.AllowedEvents)`n"
            $text += "  - Blocked: $($ReportData.BlockedEvents)`n"
            $text += "  - Audited: $($ReportData.AuditedEvents)`n"
            $text += "`n"

            if ($ReportData.TopViolatingApps -and $ReportData.TopViolatingApps.Count -gt 0) {
                $text += "TOP VIOLATING APPLICATIONS`n"
                $text += "-" * 80 + "`n"
                foreach ($app in $ReportData.TopViolatingApps) {
                    $text += "  $($app.Application): $($app.ViolationCount) violations ($($app.Percentage)%)`n"
                }
                $text += "`n"
            }
        }
        "Technical" {
            $text += "TECHNICAL DETAILS`n"
            $text += "-" * 80 + "`n"
            $text += "Total Events: $($ReportData.TotalEvents)`n`n"

            if ($ReportData.EventsByType) {
                $text += "Events by Type:`n"
                foreach ($type in $ReportData.EventsByType) {
                    $text += "  $($type.Type): $($type.Count) ($($type.Percentage)%)`n"
                }
                $text += "`n"
            }
        }
    }

    $text += "`n" + "=" * 80 + "`n"
    $text += "End of Report`n"
    $text += "=" * 80 + "`n"

    return $text
}

function Format-ReportAsHtml {
    <#
    .SYNOPSIS
        Formats report data as HTML with CSS styling

    .PARAMETER ReportData
        Report data object

    .OUTPUTS
        String containing HTML report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ReportData
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>$($ReportData.ReportTitle)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; }
        .metadata { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-label { font-weight: bold; color: #7f8c8d; }
        .metric-value { font-size: 1.2em; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background-color: #3498db; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background-color: #f8f9fa; }
        .risk-low { color: #27ae60; font-weight: bold; }
        .risk-medium { color: #f39c12; font-weight: bold; }
        .risk-high { color: #e74c3c; font-weight: bold; }
        .risk-critical { color: #c0392b; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>$($ReportData.ReportTitle)</h1>
        <div class="metadata">
            <strong>Generated:</strong> $($ReportData.GeneratedAt)<br>
            <strong>Generated By:</strong> $($ReportData.GeneratedBy)<br>
            <strong>Computer:</strong> $($ReportData.ComputerName)<br>
            <strong>Period:</strong> $($ReportData.StartDate.ToString('yyyy-MM-dd')) to $($ReportData.EndDate.ToString('yyyy-MM-dd'))
        </div>
        <p>$($ReportData.ReportSummary)</p>
"@

    # Add type-specific content
    if ($ReportData.ReportType -eq "Executive") {
        $riskClass = switch ($ReportData.RiskLevel) {
            "Low" { "risk-low" }
            "Medium" { "risk-medium" }
            "High" { "risk-high" }
            "Critical" { "risk-critical" }
        }

        $html += @"
        <h2>Executive Summary</h2>
        <div class="metric">
            <span class="metric-label">Compliance:</span>
            <span class="metric-value">$($ReportData.OverallCompliance)%</span>
        </div>
        <div class="metric">
            <span class="metric-label">Risk Score:</span>
            <span class="metric-value $riskClass">$($ReportData.RiskScore) ($($ReportData.RiskLevel))</span>
        </div>
        <div class="metric">
            <span class="metric-label">Total Events:</span>
            <span class="metric-value">$($ReportData.TotalEvents)</span>
        </div>
"@

        if ($ReportData.TopViolatingApps -and $ReportData.TopViolatingApps.Count -gt 0) {
            $html += "<h2>Top Violating Applications</h2><table><tr><th>Application</th><th>Violations</th><th>Percentage</th></tr>"
            foreach ($app in $ReportData.TopViolatingApps) {
                $html += "<tr><td>$($app.Application)</td><td>$($app.ViolationCount)</td><td>$($app.Percentage)%</td></tr>"
            }
            $html += "</table>"
        }
    }

    $html += @"
    </div>
</body>
</html>
"@

    return $html
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'New-ComplianceReport',
    'Get-ExecutiveSummaryReport',
    'Get-DetailedTechnicalReport',
    'Get-AuditTrailReport',
    'Get-PolicyComparisonReport',
    'Get-ComplianceTrend',
    'Export-ReportToPdf',
    'Export-ReportToHtml',
    'Export-ReportToCsv'
)
