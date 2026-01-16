<#
.SYNOPSIS
    Event log data access layer

.DESCRIPTION
    Provides read-only access to Windows Event Logs for AppLocker events.
    All functions return data objects only - no modifications, no UI updates.

.NOTES
    Version: 1.0.0
    Layer: Data Access (Read-Only)
#>

function Get-AppLockerEventsRaw {
    <#
    .SYNOPSIS
        Retrieves raw AppLocker event log entries

    .DESCRIPTION
        Queries Windows Event Logs for AppLocker events and returns raw event objects.
        This is a read-only operation that does not modify any data.

    .PARAMETER ComputerName
        Target computer name (default: local computer)

    .PARAMETER MaxEvents
        Maximum number of events to retrieve (default: 100)

    .PARAMETER StartTime
        Optional start time filter for events

    .PARAMETER EndTime
        Optional end time filter for events

    .EXAMPLE
        Get-AppLockerEventsRaw -MaxEvents 50

    .EXAMPLE
        Get-AppLockerEventsRaw -ComputerName "SERVER01" -StartTime (Get-Date).AddDays(-7)
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 100,

        [Parameter()]
        [datetime]$StartTime,

        [Parameter()]
        [datetime]$EndTime
    )

    begin {
        Write-Verbose "Retrieving AppLocker events from $ComputerName (Max: $MaxEvents)"

        $logNames = @(
            'Microsoft-Windows-AppLocker/EXE and DLL',
            'Microsoft-Windows-AppLocker/MSI and Script'
        )
    }

    process {
        try {
            $allEvents = @()

            foreach ($logName in $logNames) {
                try {
                    Write-Verbose "Querying log: $logName"

                    # Build filter hashtable
                    $filterHashtable = @{
                        LogName = $logName
                    }

                    if ($StartTime) {
                        $filterHashtable['StartTime'] = $StartTime
                    }

                    if ($EndTime) {
                        $filterHashtable['EndTime'] = $EndTime
                    }

                    # Query events
                    if ($ComputerName -eq $env:COMPUTERNAME -or [string]::IsNullOrEmpty($ComputerName)) {
                        if ($StartTime -or $EndTime) {
                            $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                        } else {
                            $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                        }
                    } else {
                        if ($StartTime -or $EndTime) {
                            $events = Get-WinEvent -FilterHashtable $filterHashtable -MaxEvents $MaxEvents -ComputerName $ComputerName -ErrorAction SilentlyContinue
                        } else {
                            $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ComputerName $ComputerName -ErrorAction SilentlyContinue
                        }
                    }

                    if ($events) {
                        $allEvents += $events
                        Write-Verbose "Retrieved $($events.Count) events from $logName"
                    }
                }
                catch {
                    Write-Verbose "Could not access log '$logName': $($_.Exception.Message)"
                    # Continue to next log - don't fail on individual log errors
                }
            }

            # Sort by time and limit
            $allEvents = $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents

            Write-Verbose "Total events retrieved: $($allEvents.Count)"

            return $allEvents
        }
        catch {
            Write-Error "Failed to retrieve AppLocker events: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-EventLogNames {
    <#
    .SYNOPSIS
        Enumerates AppLocker event log names

    .DESCRIPTION
        Returns a list of available AppLocker event log names on the target computer.
        Read-only operation.

    .PARAMETER ComputerName
        Target computer name (default: local computer)

    .EXAMPLE
        Get-EventLogNames

    .EXAMPLE
        Get-EventLogNames -ComputerName "SERVER01"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        Write-Verbose "Enumerating AppLocker event logs on $ComputerName"
    }

    process {
        try {
            $expectedLogs = @(
                'Microsoft-Windows-AppLocker/EXE and DLL',
                'Microsoft-Windows-AppLocker/MSI and Script',
                'Microsoft-Windows-AppLocker/Packaged app-Deployment',
                'Microsoft-Windows-AppLocker/Packaged app-Execution'
            )

            $availableLogs = @()

            foreach ($logName in $expectedLogs) {
                try {
                    if ($ComputerName -eq $env:COMPUTERNAME) {
                        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                    } else {
                        $log = Get-WinEvent -ListLog $logName -ComputerName $ComputerName -ErrorAction Stop
                    }

                    if ($log) {
                        $availableLogs += [PSCustomObject]@{
                            LogName = $logName
                            RecordCount = $log.RecordCount
                            IsEnabled = $log.IsEnabled
                            LogMode = $log.LogMode
                            MaximumSizeInBytes = $log.MaximumSizeInBytes
                        }
                        Write-Verbose "Found log: $logName (Records: $($log.RecordCount))"
                    }
                }
                catch {
                    Write-Verbose "Log not available: $logName"
                }
            }

            return $availableLogs
        }
        catch {
            Write-Error "Failed to enumerate event logs: $($_.Exception.Message)"
            return @()
        }
    }
}

function Test-EventLogExists {
    <#
    .SYNOPSIS
        Checks if an event log exists and is accessible

    .DESCRIPTION
        Verifies that the specified event log exists and can be queried.
        Read-only operation.

    .PARAMETER ComputerName
        Target computer name (default: local computer)

    .PARAMETER LogName
        Name of the event log to check

    .EXAMPLE
        Test-EventLogExists -LogName "Microsoft-Windows-AppLocker/EXE and DLL"

    .EXAMPLE
        Test-EventLogExists -ComputerName "SERVER01" -LogName "Microsoft-Windows-AppLocker/MSI and Script"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogName
    )

    begin {
        Write-Verbose "Checking if event log exists: $LogName on $ComputerName"
    }

    process {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
            } else {
                $log = Get-WinEvent -ListLog $LogName -ComputerName $ComputerName -ErrorAction Stop
            }

            if ($log) {
                Write-Verbose "Log exists: $LogName (Enabled: $($log.IsEnabled), Records: $($log.RecordCount))"
                return $true
            }

            return $false
        }
        catch {
            Write-Verbose "Log does not exist or is not accessible: $LogName - $($_.Exception.Message)"
            return $false
        }
    }
}

function Get-AppLockerEventsForReport {
    <#
    .SYNOPSIS
        Retrieves AppLocker events formatted for report generation

    .DESCRIPTION
        Queries AppLocker events and parses them into structured objects suitable for reporting.
        Extracts event details including file paths, publishers, and event types.
        Read-only operation.

    .PARAMETER StartDate
        Start date for event query

    .PARAMETER EndDate
        End date for event query

    .PARAMETER MaxEvents
        Maximum number of events to retrieve (default: 1000)

    .EXAMPLE
        Get-AppLockerEventsForReport -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = 1000
    )

    begin {
        Write-Verbose "Retrieving AppLocker events for report from $StartDate to $EndDate"
    }

    process {
        $events = @()

        try {
            # Get AppLocker events
            $appLockerEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
                StartTime = $StartDate
                EndTime = $EndDate
            } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

            if ($appLockerEvents) {
                Write-Verbose "Processing $($appLockerEvents.Count) events"

                foreach ($event in $appLockerEvents) {
                    try {
                        $eventXml = [xml]$event.ToXml()

                        # Extract event data
                        $filePath = if ($eventXml.Event.EventData.Data[4]) {
                            $eventXml.Event.EventData.Data[4].'#text'
                        } else {
                            "Unknown"
                        }

                        $fileName = if ($filePath -ne "Unknown") {
                            Split-Path $filePath -Leaf
                        } else {
                            "Unknown"
                        }

                        $publisher = if ($eventXml.Event.EventData.Data[6]) {
                            $eventXml.Event.EventData.Data[6].'#text'
                        } else {
                            "Unknown"
                        }

                        # Determine event type
                        $eventType = switch ($event.Id) {
                            8002 { "Allowed" }
                            8003 { "Audited" }
                            8004 { "Blocked" }
                            default { "Other" }
                        }

                        $events += [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            EventId = $event.Id
                            EventType = $eventType
                            FilePath = $filePath
                            FileName = $fileName
                            Publisher = $publisher
                            UserSid = if ($eventXml.Event.EventData.Data[1]) {
                                $eventXml.Event.EventData.Data[1].'#text'
                            } else {
                                "Unknown"
                            }
                            Message = $event.Message
                        }
                    }
                    catch {
                        Write-Verbose "Failed to parse event $($event.Id): $($_.Exception.Message)"
                    }
                }
            }

            Write-Verbose "Successfully parsed $($events.Count) events"
            return $events
        }
        catch {
            Write-Warning "Error retrieving AppLocker events: $($_.Exception.Message)"
            return @()
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-AppLockerEventsRaw',
    'Get-EventLogNames',
    'Test-EventLogExists',
    'Get-AppLockerEventsForReport'
)
