# Module5-EventMonitor.psm1
# Event Monitor module for GA-AppLocker
# Monitors and backs up AppLocker events

<#
.SYNOPSIS
    Get AppLocker Events
.DESCRIPTION
    Retrieves recent AppLocker events from the event log
#>
function Get-AppLockerEvents {
    [CmdletBinding()]
    param(
        [int]$MaxEvents = 100,
        [ValidateSet('All', 'Allowed', 'Audit', 'Blocked')]
        [string]$FilterType = 'All'
    )

    $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'

    $logExists = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if (-not $logExists) {
        return @{
            success = $false
            error = 'AppLocker log not found'
            data = @()
        }
    }

    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            return @{
                success = $true
                data = @()
                message = 'No AppLocker events found'
            }
        }
        return @{
            success = $false
            error = $_.Exception.Message
            data = @()
        }
    }

    $results = @()
    foreach ($event in $events) {
        $eventId = $event.Id

        $action = switch ($eventId) {
            8002 { 'Allowed' }
            8003 { 'Audit' }
            8004 { 'Blocked' }
            default { 'Unknown' }
        }

        if ($FilterType -ne 'All' -and $action -ne $FilterType) {
            continue
        }

        $timestamp = $event.TimeCreated
        $message = $event.Message
        $filePath = ''
        if ($message -match '([A-Za-z]:[^\r\n"]+\.exe)') {
            $filePath = $matches[1]
        }

        $results += @{
            eventId = $eventId
            action = $action
            timestamp = $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            filePath = $filePath
            computerName = $event.MachineName
        }
    }

    return @{
        success = $true
        data = $results
        count = $results.Count
    }
}

<#
.SYNOPSIS
    Filter Events by Event ID
.DESCRIPTION
    Filters events by specific event ID
#>
function Filter-EventsByEventId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events,
        [Parameter(Mandatory = $true)]
        [int]$TargetEventId
    )

    if (-not $Events) {
        return @()
    }

    $filtered = $Events | Where-Object { $_.eventId -eq $TargetEventId }
    return $filtered
}

<#
.SYNOPSIS
    Filter Events by Date Range
.DESCRIPTION
    Filters events within a date range
#>
function Filter-EventsByDateRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events,
        [Parameter(Mandatory = $true)]
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )

    if (-not $Events) {
        return @()
    }

    $filtered = $Events | Where-Object {
        $eventDate = [DateTime]::Parse($_.timestamp)
        $eventDate -ge $StartDate -and $eventDate -le $EndDate
    }

    return $filtered
}

<#
.SYNOPSIS
    Backup Events from Remote Computer
.DESCRIPTION
    Saves AppLocker events from a remote computer to a file
#>
function Backup-RemoteAppLockerEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return @{
            success = $false
            error = 'Computer name required'
        }
    }

    try {
        $online = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
        if (-not $online) {
            return @{
                success = $false
                error = "Computer '$ComputerName' is not reachable"
            }
        }

        $scriptBlock = {
            $logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
            try {
                Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction Stop |
                    Select-Object Id, TimeCreated, Message, MachineName
            }
            catch {
                @()
            }
        }

        $events = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop

        if (-not $events -or $events.Count -eq 0) {
            return @{
                success = $true
                message = 'No events found on remote computer'
                count = 0
            }
        }

        $parentDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $events | Export-Clixml -Path $OutputPath -Force

        return @{
            success = $true
            path = $OutputPath
            count = $events.Count
            computerName = $ComputerName
        }
    }
    catch {
        return @{
            success = $false
            error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Backup Events from All Online Systems
.DESCRIPTION
    Backs up events from multiple computers
#>
function Backup-AllAppLockerEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ComputerNames,
        [string]$OutputFolder = 'C:\AppLocker\output\events'
    )

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $results = @()
    foreach ($computer in $ComputerNames) {
        $outputPath = Join-Path $OutputFolder "$computer-Events.xml"
        $backup = Backup-RemoteAppLockerEvents -ComputerName $computer -OutputPath $outputPath

        $results += @{
            computerName = $computer
            success = $backup.success
            path = if ($backup.success) { $outputPath } else { '' }
            count = if ($backup.success) { $backup.count } else { 0 }
            error = if (-not $backup.success) { $backup.error } else { '' }
        }
    }

    $successCount = ($results | Where-Object { $_.success }).Count
    $totalEvents = ($results | Measure-Object -Property count -Sum).Sum

    return @{
        success = $true
        results = $results
        totalComputers = $ComputerNames.Count
        successfulBackups = $successCount
        totalEvents = $totalEvents
    }
}

# Export functions
Export-ModuleMember -Function Get-AppLockerEvents, Filter-EventsByEventId, Filter-EventsByDateRange,
                              Backup-RemoteAppLockerEvents, Backup-AllAppLockerEvents
