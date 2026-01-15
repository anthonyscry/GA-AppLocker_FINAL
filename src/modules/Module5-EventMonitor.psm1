# Module5-EventMonitor.psm1
# Event Monitor module for GA-AppLocker
# Monitors and backs up AppLocker events
# Enhanced with patterns from Microsoft AaronLocker

# Import Common library
Import-Module (Join-Path $PSScriptRoot '..\lib\Common.psm1') -ErrorAction SilentlyContinue

# Event ID mappings (from AaronLocker)
$script:EventIdMapping = @{
    ExeDllAllowed  = 8002
    ExeDllWarning  = 8003
    ExeDllError    = 8004
    MsiScriptAllowed = 8005
    MsiScriptWarning = 8006
    MsiScriptError   = 8007
    PkgdAppAllowed = 8020
    PkgdAppWarning = 8021
    PkgdAppError   = 8022
}

# PowerShell policy test file hash patterns (from AaronLocker)
$script:PsPolicyTestFileHash1 = "0x6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B"
$script:PsPolicyTestFileHash2 = "0x96AD1146EB96877EAB5942AE0736B82D8B5E2039A80D3D6932665C1A4C87DCF7"

<#
.SYNOPSIS
    Get AppLocker Events
.DESCRIPTION
    Retrieves recent AppLocker events from the event log with enhanced data extraction
.PARAMETER ComputerName
    Optional remote computer name
.PARAMETER MaxEvents
    Maximum number of events to retrieve
.PARAMETER FilterType
    Filter by event type (Allowed/Audit/Blocked/All)
.PARAMETER IncludeMsiScript
    Also retrieve MSI and Script events
.PARAMETER NoPSFilter
    Don't filter out PowerShell policy test files
#>
function Get-AppLockerEvents {
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [int]$MaxEvents = 100,
        [ValidateSet('All', 'Allowed', 'Audit', 'Blocked')]
        [string]$FilterType = 'All',
        [switch]$IncludeMsiScript,
        [switch]$NoPSFilter
    )

    $logNames = @('Microsoft-Windows-AppLocker/EXE and DLL')
    if ($IncludeMsiScript) {
        $logNames += 'Microsoft-Windows-AppLocker/MSI and Script'
    }

    # Build XPath filter
    $logEventIdFilter = switch ($FilterType) {
        'Allowed' { "$($script:EventIdMapping.ExeDllAllowed) or $($script:EventIdMapping.MsiScriptAllowed)" }
        'Audit'   { "$($script:EventIdMapping.ExeDllWarning) or $($script:EventIdMapping.MsiScriptWarning)" }
        'Blocked' { "$($script:EventIdMapping.ExeDllError) or $($script:EventIdMapping.MsiScriptError)" }
        default   { "$($script:EventIdMapping.ExeDllWarning) or $($script:EventIdMapping.ExeDllError) or $($script:EventIdMapping.ExeDllAllowed)" }
    }

    if ($IncludeMsiScript) {
        $logEventIdFilter = switch ($FilterType) {
            'Allowed' { "$logEventIdFilter or $($script:EventIdMapping.MsiScriptAllowed)" }
            'Audit'   { "$logEventIdFilter or $($script:EventIdMapping.MsiScriptWarning)" }
            'Blocked' { "$logEventIdFilter or $($script:EventIdMapping.MsiScriptError)" }
            default   { "$logEventIdFilter or $($script:EventIdMapping.MsiScriptAllowed) or $($script:EventIdMapping.MsiScriptWarning) or $($script:EventIdMapping.MsiScriptError)" }
        }
    }

    $filter = "*[System[(EventID=($logEventIdFilter))]]"

    $results = @()
    $filteredOut = 0

    try {
        foreach ($logName in $logNames) {
            $params = @{
                FilterXPath = $filter
                ErrorAction = 'SilentlyContinue'
            }

            if ($ComputerName) {
                $params['ComputerName'] = $ComputerName
                $params['LogName'] = $logName
            }
            else {
                $params['LogName'] = $logName
            }

            $logEvents = Get-WinEvent @params -MaxEvents $MaxEvents

            foreach ($logEvent in $logEvents) {
                # Property selector for efficient extraction (from AaronLocker)
                $selectorStrings = @(
                    'Event/UserData/RuleAndFileData/PolicyName',
                    'Event/UserData/RuleAndFileData/TargetUser',
                    'Event/UserData/RuleAndFileData/TargetProcessId',
                    'Event/UserData/RuleAndFileData/Fqbn',
                    'Event/UserData/RuleAndFileData/FilePath',
                    'Event/UserData/RuleAndFileData/FileHash'
                )

                $propertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($selectorStrings)
                $properties = $logEvent.GetPropertyValues($propertySelector)

                $fileType = if ($properties[0]) { $properties[0] } else { "EXE" }
                $userSid = if ($properties[1]) { $properties[1].ToString() } else { "" }
                $userName = ConvertFrom-SidCached -Sid $userSid
                $processId = if ($properties[2]) { $properties[2].ToString() } else { "" }
                $filePath = if ($properties[4]) { $properties[4] } else { "" }
                $hashRaw = $properties[5]

                # Convert hash to proper format
                $hash = ""
                if ($hashRaw) {
                    if ($hashRaw -is [string]) {
                        $hash = if ($hashRaw.StartsWith("0x")) { $hashRaw } else { "0x" + $hashRaw }
                    }
                    elseif ($hashRaw.Length -gt 0) {
                        $hash = "0x" + [System.BitConverter]::ToString($hashRaw).Replace('-', '')
                    }
                }

                # Extract publisher info from FQBN (from AaronLocker pattern)
                $publisherName = ""
                $productName = ""
                $binaryName = ""
                $fileVersion = ""

                if ($properties[3] -and $properties[3] -ne "-") {
                    $pubInfo = $properties[3].Split("\")
                    $publisherName = if ($pubInfo.Count -gt 0) { $pubInfo[0] } else { "" }
                    $productName = if ($pubInfo.Count -gt 1) { $pubInfo[1] } else { "" }
                    $binaryName = if ($pubInfo.Count -gt 2) { $pubInfo[2] } else { "" }
                    $fileVersion = if ($pubInfo.Count -gt 3) { $pubInfo[3] } else { "" }
                }

                # Filter out PowerShell policy test files (from AaronLocker)
                $filterOut = $false
                if (-not $NoPSFilter -and $fileType -eq "SCRIPT") {
                    if ($hash -eq $script:PsPolicyTestFileHash1 -or
                        $hash -eq $script:PsPolicyTestFileHash2 -or
                        $filePath -match "\\APPDATA\\LOCAL\\TEMP\\(__PSScriptPolicyTest_)?[A-Z0-9]{8}\.[A-Z0-9]{3}\.PS") {
                        $filterOut = $true
                    }
                }

                if ($filterOut) {
                    $filteredOut++
                    continue
                }

                # Determine action type
                $action = switch ($logEvent.Id) {
                    { $_ -in $script:EventIdMapping.ExeDllAllowed, $script:EventIdMapping.MsiScriptAllowed } { 'Allowed' }
                    { $_ -in $script:EventIdMapping.ExeDllWarning, $script:EventIdMapping.MsiScriptWarning } { 'Audit' }
                    { $_ -in $script:EventIdMapping.ExeDllError, $script:EventIdMapping.MsiScriptError } { 'Blocked' }
                    default { 'Unknown' }
                }

                # Convert to generic path (from AaronLocker pattern)
                $genericPath = ConvertTo-AppLockerGenericPath -FilePath $filePath
                $fileName = [System.IO.Path]::GetFileName($filePath)
                $fileExt = [System.IO.Path]::GetExtension($filePath)

                $results += @{
                    eventId = $logEvent.Id
                    action = $action
                    timestamp = $logEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    timestampSortable = $logEvent.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffffff')
                    filePath = $filePath
                    genericPath = $genericPath
                    fileName = $fileName
                    fileExt = $fileExt
                    fileType = $fileType
                    userSid = $userSid
                    userName = $userName
                    computerName = $logEvent.MachineName
                    pid = $processId
                    publisherName = $publisherName
                    productName = $productName
                    binaryName = $binaryName
                    fileVersion = $fileVersion
                    hash = $hash
                    isSigned = ($publisherName -ne "" -and $publisherName -ne "-")
                }
            }
        }

        return @{
            success = $true
            data = $results
            count = $results.Count
            filteredOut = $filteredOut
        }
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
        $logEventDate = [DateTime]::Parse($_.timestamp)
        $logEventDate -ge $StartDate -and $logEventDate -le $EndDate
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

        $logEvents = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction Stop

        if (-not $logEvents -or $logEvents.Count -eq 0) {
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

        $logEvents | Export-Clixml -Path $OutputPath -Force

        return @{
            success = $true
            path = $OutputPath
            count = $logEvents.Count
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
