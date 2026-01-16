<#
.SYNOPSIS
    AppLocker event processing business logic

.DESCRIPTION
    Core functions for retrieving, parsing, and processing AppLocker events.
    Provides event aggregation, statistics, deduplication, and remote event collection.

.NOTES
    Module Name: EventProcessor
    Author: GA-AppLocker Team
    Version: 1.0.0
    Dependencies: None (pure business logic)

.EXAMPLE
    Import-Module .\EventProcessor.ps1

    # Get local AppLocker events
    $result = Get-AppLockerEvents -MaxEvents 100
    if ($result.success) {
        Write-Host "Found $($result.count) events"
        $result.data | Format-Table -AutoSize
    }

.EXAMPLE
    # Get events from remote computers
    $computers = @("Server01", "Server02")
    $result = Get-RemoteAppLockerEvents -ComputerNames $computers -MaxEventsPerComputer 50
    Write-Host "Total events from all computers: $($result.totalEvents)"

.LINK
    https://github.com/yourusername/GA-AppLocker
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# PUBLIC FUNCTIONS
# ============================================================

function Get-AppLockerEvents {
    <#
    .SYNOPSIS
        Retrieves AppLocker events from local or remote computer

    .DESCRIPTION
        Queries Windows Event Logs for AppLocker events (EXE/DLL and MSI/Script).
        Returns parsed event data with deduplication and sanitization.

    .PARAMETER MaxEvents
        Maximum number of events to retrieve per log (default: 100)

    .PARAMETER ComputerName
        Computer name to query (default: local computer)

    .PARAMETER StartDate
        Filter events after this date

    .PARAMETER EndDate
        Filter events before this date

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - data: Array of event objects
        - count: Number of events
        - computerName: Source computer name
        - error: Error message (if failure)

    .EXAMPLE
        $result = Get-AppLockerEvents -MaxEvents 50
        foreach ($event in $result.data) {
            Write-Host "$($event.time) - $($event.eventId): $($event.message)"
        }

    .EXAMPLE
        # Get events from last 7 days
        $startDate = (Get-Date).AddDays(-7)
        $result = Get-AppLockerEvents -StartDate $startDate -MaxEvents 500

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Basic event retrieval
        $result = Get-AppLockerEvents -MaxEvents 10
        Assert ($result.success -eq $true)
        Assert ($result.data -is [array])
        Assert ($result.count -ge 0)

        # Test: Event structure
        if ($result.count -gt 0) {
            $event = $result.data[0]
            Assert ($event.computerName -ne $null)
            Assert ($event.eventId -ne $null)
            Assert ($event.time -ne $null)
        }
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 100,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $false)]
        [datetime]$EndDate
    )

    try {
        $logNames = @(
            'Microsoft-Windows-AppLocker/EXE and DLL',
            'Microsoft-Windows-AppLocker/MSI and Script'
        )

        $allEvents = @()
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or [string]::IsNullOrEmpty($ComputerName)

        foreach ($logName in $logNames) {
            try {
                # Build filter hashtable
                $filterHash = @{
                    LogName = $logName
                    MaxEvents = $MaxEvents
                }

                if (-not $isLocal) {
                    $filterHash['ComputerName'] = $ComputerName
                }

                if ($StartDate) {
                    $filterHash['StartTime'] = $StartDate
                }

                if ($EndDate) {
                    $filterHash['EndTime'] = $EndDate
                }

                $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue

                if ($events) {
                    foreach ($event in $events) {
                        # Sanitize message (remove newlines, carriage returns)
                        $sanitizedMessage = $event.Message -replace "`n", " " -replace "`r", "" -replace "\s+", " "

                        # HTML encode for security
                        $encodedMessage = if ($sanitizedMessage) {
                            [System.Web.HttpUtility]::HtmlEncode($sanitizedMessage)
                        } else {
                            "No message"
                        }

                        # Determine event level
                        $level = switch ($event.Level) {
                            1 { "Critical" }
                            2 { "Error" }
                            3 { "Warning" }
                            4 { "Information" }
                            default { "Info" }
                        }

                        # Parse event type from ID
                        $eventType = switch ($event.Id) {
                            8002 { "Allowed" }
                            8003 { "Audited" }
                            8004 { "Blocked" }
                            8005 { "Allowed (Audit)" }
                            8006 { "Denied (MSI)" }
                            8007 { "Audited (MSI)" }
                            default { "Other" }
                        }

                        $allEvents += @{
                            computerName = $ComputerName
                            logName = $logName -replace 'Microsoft-Windows-AppLocker/', ''
                            eventId = $event.Id
                            eventType = $eventType
                            time = $event.TimeCreated
                            timeString = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                            level = $level
                            message = $encodedMessage
                            originalMessage = $sanitizedMessage
                        }
                    }
                }
            }
            catch {
                # Log error but continue with other logs
                Write-Verbose "Error reading log '$logName': $($_.Exception.Message)"
            }
        }

        # Sort by time (most recent first)
        $allEvents = $allEvents | Sort-Object { $_.time } -Descending | Select-Object -First $MaxEvents

        return @{
            success = $true
            data = $allEvents
            count = $allEvents.Count
            computerName = $ComputerName
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to retrieve AppLocker events: $($_.Exception.Message)"
            exception = $_.Exception
            data = @()
            count = 0
            computerName = $ComputerName
        }
    }
}

function Get-RemoteAppLockerEvents {
    <#
    .SYNOPSIS
        Retrieves AppLocker events from multiple remote computers via WinRM

    .DESCRIPTION
        Queries multiple remote computers in parallel using Invoke-Command
        and aggregates all events into a single result set.

    .PARAMETER ComputerNames
        Array of computer names to query

    .PARAMETER MaxEventsPerComputer
        Maximum events to retrieve from each computer (default: 50)

    .PARAMETER Credential
        PSCredential for remote authentication (optional)

    .OUTPUTS
        Hashtable with keys:
        - success: Boolean
        - data: Array of all events from all computers
        - totalEvents: Total event count
        - computers: Array of computer results
        - failedComputers: Array of computers that failed
        - error: Error message (if failure)

    .EXAMPLE
        $computers = @("Server01", "Server02", "Server03")
        $result = Get-RemoteAppLockerEvents -ComputerNames $computers
        Write-Host "Retrieved $($result.totalEvents) events from $($result.computers.Count) computers"

    .EXAMPLE
        # Use credentials
        $cred = Get-Credential
        $result = Get-RemoteAppLockerEvents -ComputerNames $computers -Credential $cred

    .NOTES
        Requires WinRM to be enabled on target computers.

        Unit Test Example:
        ```powershell
        # Test: Remote event collection
        $result = Get-RemoteAppLockerEvents -ComputerNames @($env:COMPUTERNAME)
        Assert ($result.success -eq $true)
        Assert ($result.computers.Count -eq 1)
        Assert ($result.failedComputers.Count -eq 0)

        # Test: Failed computer handling
        $result = Get-RemoteAppLockerEvents -ComputerNames @("InvalidComputer123")
        Assert ($result.failedComputers.Count -eq 1)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerNames,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$MaxEventsPerComputer = 50,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        $allEvents = @()
        $computerResults = @()
        $failedComputers = @()

        $scriptBlock = {
            param($MaxEvents)

            $logNames = @(
                'Microsoft-Windows-AppLocker/EXE and DLL',
                'Microsoft-Windows-AppLocker/MSI and Script'
            )

            $events = @()
            foreach ($logName in $logNames) {
                try {
                    $logEvents = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                    if ($logEvents) {
                        foreach ($event in $logEvents) {
                            $sanitizedMessage = $event.Message -replace "`n", " " -replace "`r", "" -replace "\s+", " "
                            $encodedMessage = if ($sanitizedMessage) {
                                [System.Web.HttpUtility]::HtmlEncode($sanitizedMessage)
                            } else {
                                "No message"
                            }

                            $eventType = switch ($event.Id) {
                                8002 { "Allowed" }
                                8003 { "Audited" }
                                8004 { "Blocked" }
                                8005 { "Allowed (Audit)" }
                                8006 { "Denied (MSI)" }
                                8007 { "Audited (MSI)" }
                                default { "Other" }
                            }

                            $events += @{
                                logName = $logName -replace 'Microsoft-Windows-AppLocker/', ''
                                eventId = $event.Id
                                eventType = $eventType
                                time = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                                level = $event.LevelDisplayName
                                message = $encodedMessage
                            }
                        }
                    }
                }
                catch {
                    # Continue with next log
                }
            }
            return $events
        }

        foreach ($computer in $ComputerNames) {
            try {
                $invokeParams = @{
                    ComputerName = $computer
                    ScriptBlock = $scriptBlock
                    ArgumentList = $MaxEventsPerComputer
                    ErrorAction = 'Stop'
                }

                if ($Credential) {
                    $invokeParams['Credential'] = $Credential
                }

                $computerEvents = Invoke-Command @invokeParams

                if ($computerEvents) {
                    # Add computer name to each event
                    foreach ($evt in $computerEvents) {
                        $evt.computerName = $computer
                        $allEvents += $evt
                    }

                    $computerResults += @{
                        name = $computer
                        eventCount = $computerEvents.Count
                        status = "Success"
                    }
                }
                else {
                    $computerResults += @{
                        name = $computer
                        eventCount = 0
                        status = "Success (No events)"
                    }
                }
            }
            catch {
                $failedComputers += @{
                    name = $computer
                    error = $_.Exception.Message
                }
            }
        }

        # Sort all events by time (most recent first)
        $allEvents = $allEvents | Sort-Object { $_.time } -Descending

        return @{
            success = $true
            data = $allEvents
            totalEvents = $allEvents.Count
            computers = $computerResults
            failedComputers = $failedComputers
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to retrieve remote AppLocker events: $($_.Exception.Message)"
            exception = $_.Exception
            data = @()
            totalEvents = 0
            computers = @()
            failedComputers = @()
        }
    }
}

function Get-AppLockerEventsForReport {
    <#
    .SYNOPSIS
        Retrieves and enriches AppLocker events for compliance reporting

    .DESCRIPTION
        Advanced event retrieval with detailed parsing of XML event data.
        Extracts file path, publisher, user SID, and other metadata from events.

    .PARAMETER StartDate
        Start date for event filter

    .PARAMETER EndDate
        End date for event filter

    .PARAMETER MaxEvents
        Maximum number of events to retrieve (default: 5000)

    .OUTPUTS
        Array of enriched event objects with properties:
        - TimeCreated, EventId, EventType, FilePath, FileName, Publisher, UserSid, Message

    .EXAMPLE
        $startDate = (Get-Date).AddDays(-30)
        $endDate = Get-Date
        $events = Get-AppLockerEventsForReport -StartDate $startDate -EndDate $endDate
        Write-Host "Retrieved $($events.Count) events for reporting"

    .NOTES
        Unit Test Example:
        ```powershell
        # Test: Report event structure
        $events = Get-AppLockerEventsForReport -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date)
        Assert ($events -is [array])

        if ($events.Count -gt 0) {
            $event = $events[0]
            Assert ($event.TimeCreated -ne $null)
            Assert ($event.EventType -ne $null)
        }
        ```
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 50000)]
        [int]$MaxEvents = 5000
    )

    $events = @()

    try {
        # Query AppLocker event logs
        $filterHash = @{
            LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
            StartTime = $StartDate
            EndTime = $EndDate
        }

        $appLockerEvents = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        if ($appLockerEvents) {
            foreach ($event in $appLockerEvents) {
                try {
                    # Parse event XML for detailed data
                    $eventXml = [xml]$event.ToXml()

                    # Extract file information from event data
                    $filePath = "Unknown"
                    $fileName = "Unknown"
                    $publisher = "Unknown"
                    $userSid = "Unknown"

                    if ($eventXml.Event.EventData.Data) {
                        # Different event IDs have different data structures
                        # Attempt to extract common fields
                        $dataArray = $eventXml.Event.EventData.Data

                        # Try to find file path (usually in position 4 or 5)
                        if ($dataArray[4] -and $dataArray[4].'#text') {
                            $filePath = $dataArray[4].'#text'
                            $fileName = Split-Path $filePath -Leaf
                        }
                        elseif ($dataArray[5] -and $dataArray[5].'#text') {
                            $filePath = $dataArray[5].'#text'
                            $fileName = Split-Path $filePath -Leaf
                        }

                        # Try to find publisher (usually in position 6 or 7)
                        if ($dataArray[6] -and $dataArray[6].'#text') {
                            $publisher = $dataArray[6].'#text'
                        }
                        elseif ($dataArray[7] -and $dataArray[7].'#text') {
                            $publisher = $dataArray[7].'#text'
                        }

                        # User SID (usually in position 1)
                        if ($dataArray[1] -and $dataArray[1].'#text') {
                            $userSid = $dataArray[1].'#text'
                        }
                    }

                    # Determine event type from ID
                    $eventType = switch ($event.Id) {
                        8002 { "Allowed" }
                        8003 { "Audited" }
                        8004 { "Blocked" }
                        8005 { "Allowed (Audit)" }
                        8006 { "Denied (MSI)" }
                        8007 { "Audited (MSI)" }
                        default { "Other" }
                    }

                    $events += [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        EventId = $event.Id
                        EventType = $eventType
                        FilePath = $filePath
                        FileName = $fileName
                        Publisher = $publisher
                        UserSid = $userSid
                        Message = $event.Message
                    }
                }
                catch {
                    # Skip events that fail to parse
                    Write-Verbose "Failed to parse event: $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Verbose "Error retrieving AppLocker events: $($_.Exception.Message)"
    }

    return $events
}

function Get-EventStatistics {
    <#
    .SYNOPSIS
        Calculates statistics from AppLocker event data

    .DESCRIPTION
        Aggregates event data and computes statistics like counts by type,
        top applications, top users, and trends.

    .PARAMETER Events
        Array of event objects from Get-AppLockerEvents or Get-AppLockerEventsForReport

    .OUTPUTS
        Hashtable with statistics:
        - totalEvents, allowedCount, blockedCount, auditedCount
        - topApplications, topUsers, eventsByDay, eventsByHour

    .EXAMPLE
        $result = Get-AppLockerEvents -MaxEvents 1000
        $stats = Get-EventStatistics -Events $result.data
        Write-Host "Blocked events: $($stats.blockedCount)"

    .NOTES
        Unit Test Example:
        ```powershell
        # Create mock events
        $events = @(
            @{ eventType = "Blocked"; fileName = "app1.exe"; userSid = "S-1-5-21-123" },
            @{ eventType = "Allowed"; fileName = "app2.exe"; userSid = "S-1-5-21-456" },
            @{ eventType = "Blocked"; fileName = "app1.exe"; userSid = "S-1-5-21-123" }
        )

        $stats = Get-EventStatistics -Events $events
        Assert ($stats.totalEvents -eq 3)
        Assert ($stats.blockedCount -eq 2)
        Assert ($stats.allowedCount -eq 1)
        ```
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Events
    )

    try {
        $totalEvents = $Events.Count
        $allowedCount = ($Events | Where-Object { $_.eventType -eq "Allowed" -or $_.EventType -eq "Allowed" }).Count
        $blockedCount = ($Events | Where-Object { $_.eventType -eq "Blocked" -or $_.EventType -eq "Blocked" }).Count
        $auditedCount = ($Events | Where-Object { $_.eventType -eq "Audited" -or $_.EventType -eq "Audited" }).Count

        # Top applications (by event count)
        $topApplications = $Events |
            Where-Object { $_.fileName -or $_.FileName } |
            Group-Object -Property { if ($_.fileName) { $_.fileName } else { $_.FileName } } |
            Sort-Object -Property Count -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                [PSCustomObject]@{
                    Application = $_.Name
                    Count = $_.Count
                    Percentage = if ($totalEvents -gt 0) { [math]::Round(($_.Count / $totalEvents) * 100, 2) } else { 0 }
                }
            }

        # Top users (by event count)
        $topUsers = $Events |
            Where-Object { $_.userSid -or $_.UserSid } |
            Group-Object -Property { if ($_.userSid) { $_.userSid } else { $_.UserSid } } |
            Sort-Object -Property Count -Descending |
            Select-Object -First 10 |
            ForEach-Object {
                [PSCustomObject]@{
                    UserSid = $_.Name
                    Count = $_.Count
                }
            }

        # Events by day (if time data available)
        $eventsByDay = $Events |
            Where-Object { $_.time -or $_.TimeCreated } |
            Group-Object -Property { if ($_.time) { $_.time.ToString("yyyy-MM-dd") } else { $_.TimeCreated.ToString("yyyy-MM-dd") } } |
            Sort-Object -Property Name |
            ForEach-Object {
                [PSCustomObject]@{
                    Date = $_.Name
                    Count = $_.Count
                }
            }

        return @{
            success = $true
            totalEvents = $totalEvents
            allowedCount = $allowedCount
            blockedCount = $blockedCount
            auditedCount = $auditedCount
            topApplications = $topApplications
            topUsers = $topUsers
            eventsByDay = $eventsByDay
        }
    }
    catch {
        return @{
            success = $false
            error = "Failed to calculate event statistics: $($_.Exception.Message)"
            exception = $_.Exception
        }
    }
}

function Remove-DuplicateEvents {
    <#
    .SYNOPSIS
        Removes duplicate events based on key fields

    .DESCRIPTION
        Deduplicates event array based on eventId, time, and message.
        Useful for cleaning up event data from multiple sources.

    .PARAMETER Events
        Array of event objects

    .PARAMETER DeduplicationKey
        Properties to use for deduplication (default: eventId, time, message)

    .OUTPUTS
        Array of unique events

    .EXAMPLE
        $events = Get-AppLockerEvents -MaxEvents 500
        $uniqueEvents = Remove-DuplicateEvents -Events $events.data
        Write-Host "Removed $($events.data.Count - $uniqueEvents.Count) duplicates"

    .NOTES
        Unit Test Example:
        ```powershell
        # Create duplicate events
        $events = @(
            @{ eventId = 8004; time = "2024-01-01 10:00:00"; message = "Test" },
            @{ eventId = 8004; time = "2024-01-01 10:00:00"; message = "Test" },
            @{ eventId = 8003; time = "2024-01-01 11:00:00"; message = "Other" }
        )

        $unique = Remove-DuplicateEvents -Events $events
        Assert ($unique.Count -eq 2)
        ```
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$Events,

        [Parameter(Mandatory = $false)]
        [string[]]$DeduplicationKey = @('eventId', 'time', 'message')
    )

    try {
        if ($Events.Count -eq 0) {
            return @()
        }

        $seen = @{}
        $uniqueEvents = @()

        foreach ($event in $Events) {
            # Build composite key from specified properties
            $keyParts = @()
            foreach ($prop in $DeduplicationKey) {
                if ($event.$prop) {
                    $keyParts += $event.$prop.ToString()
                }
            }

            $compositeKey = $keyParts -join '|'

            if (-not $seen.ContainsKey($compositeKey)) {
                $seen[$compositeKey] = $true
                $uniqueEvents += $event
            }
        }

        return $uniqueEvents
    }
    catch {
        Write-Verbose "Error during deduplication: $($_.Exception.Message)"
        return $Events
    }
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function ConvertTo-HtmlEncoded {
    <#
    .SYNOPSIS
        HTML encodes a string for safe display

    .PARAMETER Value
        String to encode

    .OUTPUTS
        HTML-encoded string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        return ""
    }

    try {
        return [System.Web.HttpUtility]::HtmlEncode($Value)
    }
    catch {
        # Fallback to manual encoding
        return $Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
    }
}

# ============================================================
# MODULE EXPORTS
# ============================================================

Export-ModuleMember -Function @(
    'Get-AppLockerEvents',
    'Get-RemoteAppLockerEvents',
    'Get-AppLockerEventsForReport',
    'Get-EventStatistics',
    'Remove-DuplicateEvents'
)
