# ============================================================
# GA-AppLocker SIEM Integration Module - Phase 5
# Complete implementation for SIEM log forwarding
# ============================================================

# ============================================================
# PART 1: SIEM FORWARDING FUNCTIONS
# ============================================================

# Global variables for SIEM integration
$script:SiemConfig = @{
    Enabled = $false
    SiemType = "Splunk"
    Server = ""
    Port = 8088
    Protocol = "HTTPS"
    AuthType = "Token"
    Token = ""
    Username = ""
    Password = ""
    UseSSL = $true
    BatchSize = 100
    MaxRetries = 3
    RetryDelay = 5
    FallbackEndpoint = ""
    Filters = @{
        Allowed = $true
        Blocked = $true
        Audited = $true
        MinSeverity = "All"
        IncludePattern = $null
        ExcludePattern = $null
    }
    Enrichment = @{
        AddHostMetadata = $true
        AddADInfo = $false
        AddThreatIntel = $false
        NormalizeTimestamps = $true
    }
}

$script:SiemStatistics = @{
    EventsSent = 0
    EventsFailed = 0
    QueueSize = 0
    LastEventTime = $null
    StartTime = $null
    EventsPerMinute = 0
    Status = "Stopped"
}

$script:SiemEventQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$script:SiemForwarderJob = $null
$script:SiemConfigPath = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Config.xml"

<#
.SYNOPSIS
    Send a single AppLocker event to SIEM

.PARAMETER Event
    The event object to send

.PARAMETER Config
    SIEM configuration (uses global config if not specified)

.EXAMPLE
    Send-SiemEvent -Event $appLockerEvent
#>
function Send-SiemEvent {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    try {
        # Format event based on SIEM type
        $formattedEvent = Format-EventForSiem -Event $Event -SiemType $Config.SiemType -Config $Config

        # Send based on protocol
        $result = switch ($Config.Protocol) {
            "HTTPS" { Send-HttpEvent -FormattedEvent $formattedEvent -Config $Config }
            "HTTP"  { Send-HttpEvent -FormattedEvent $formattedEvent -Config $Config }
            "TCP"   { Send-TcpEvent -FormattedEvent $formattedEvent -Config $Config }
            "UDP"   { Send-UdpEvent -FormattedEvent $formattedEvent -Config $Config }
            default { throw "Unsupported protocol: $($Config.Protocol)" }
        }

        if ($result.Success) {
            $script:SiemStatistics.EventsSent++
            $script:SiemStatistics.LastEventTime = Get-Date
            Write-SiemLog "Event sent successfully: $($Event.Id)" -Level "INFO"
            return @{ Success = $true; Message = "Event sent successfully" }
        } else {
            $script:SiemStatistics.EventsFailed++
            Write-SiemLog "Failed to send event: $($result.Error)" -Level "ERROR"

            # Try fallback endpoint
            if ($Config.FallbackEndpoint) {
                Write-SiemLog "Attempting fallback endpoint..." -Level "WARN"
                $fallbackConfig = $Config.Clone()
                $fallbackConfig.Server = $Config.FallbackEndpoint
                return Send-SiemEvent -Event $Event -Config $fallbackConfig
            }

            return @{ Success = $false; Error = $result.Error }
        }
    } catch {
        $script:SiemStatistics.EventsFailed++
        Write-SiemLog "Error sending event: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Send multiple events to SIEM in batch

.PARAMETER Events
    Array of events to send

.PARAMETER Config
    SIEM configuration

.EXAMPLE
    Send-BatchEvents -Events $eventArray
#>
function Send-BatchEvents {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    if (-not $Events -or $Events.Count -eq 0) {
        return @{ Success = $true; Sent = 0; Failed = 0; Message = "No events to send" }
    }

    $batchSize = $Config.BatchSize
    $totalEvents = $Events.Count
    $sentCount = 0
    $failedCount = 0

    Write-SiemLog "Sending batch of $totalEvents events (batch size: $batchSize)" -Level "INFO"

    # Split into batches
    for ($i = 0; $i -lt $totalEvents; $i += $batchSize) {
        $batch = $Events[$i..[Math]::Min($i + $batchSize - 1, $totalEvents - 1)]
        $retryCount = 0
        $success = $false

        # Retry logic
        while (-not $success -and $retryCount -lt $Config.MaxRetries) {
            try {
                # Format batch based on SIEM type
                $formattedBatch = Format-BatchForSiem -Events $batch -SiemType $Config.SiemType -Config $Config

                # Send batch
                $result = switch ($Config.Protocol) {
                    "HTTPS" { Send-HttpBatch -FormattedBatch $formattedBatch -Config $Config }
                    "HTTP"  { Send-HttpBatch -FormattedBatch $formattedBatch -Config $Config }
                    default {
                        # For TCP/UDP, send events individually
                        $batchSent = 0
                        foreach ($evt in $batch) {
                            $evtResult = Send-SiemEvent -Event $evt -Config $Config
                            if ($evtResult.Success) { $batchSent++ }
                        }
                        @{ Success = $true; Sent = $batchSent }
                    }
                }

                if ($result.Success) {
                    $sentCount += $batch.Count
                    $script:SiemStatistics.EventsSent += $batch.Count
                    $success = $true
                    Write-SiemLog "Batch sent: $($batch.Count) events" -Level "INFO"
                } else {
                    $retryCount++
                    if ($retryCount -lt $Config.MaxRetries) {
                        Write-SiemLog "Batch failed, retrying ($retryCount/$($Config.MaxRetries))..." -Level "WARN"
                        Start-Sleep -Seconds $Config.RetryDelay
                    }
                }
            } catch {
                $retryCount++
                Write-SiemLog "Batch error: $($_.Exception.Message)" -Level "ERROR"
                if ($retryCount -lt $Config.MaxRetries) {
                    Start-Sleep -Seconds $Config.RetryDelay
                }
            }
        }

        if (-not $success) {
            $failedCount += $batch.Count
            $script:SiemStatistics.EventsFailed += $batch.Count
            Write-SiemLog "Batch failed after retries: $($batch.Count) events" -Level "ERROR"
        }
    }

    return @{
        Success = $true
        Sent = $sentCount
        Failed = $failedCount
        Total = $totalEvents
        Message = "Batch processing complete: $sentCount sent, $failedCount failed"
    }
}

<#
.SYNOPSIS
    Format event for Splunk HEC

.PARAMETER Event
    The event to format

.PARAMETER Config
    SIEM configuration
#>
function Format-EventForSplunk {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config
    )

    $enrichedEvent = Add-EventEnrichment -Event $Event -Config $Config

    $splunkEvent = @{
        time = if ($Config.Enrichment.NormalizeTimestamps) {
            (Get-Date $enrichedEvent.TimeCreated).ToUniversalTime()
        } else {
            Get-Date $enrichedEvent.TimeCreated
        }
        host = $enrichedEvent.ComputerName
        source = "AppLocker"
        sourcetype = "WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL"
        event = @{
            EventId = $enrichedEvent.Id
            Level = $enrichedEvent.LevelDisplayName
            Message = $enrichedEvent.Message
            TimeCreated = $enrichedEvent.TimeCreated
            UserId = $enrichedEvent.UserId
            UserName = $enrichedEvent.UserName
            ProcessId = $enrichedEvent.ProcessId
            FilePath = $enrichedEvent.FilePath
            FileHash = $enrichedEvent.FileHash
            PublisherName = $enrichedEvent.PublisherName
            RuleName = $enrichedEvent.RuleName
            Severity = $enrichedEvent.Severity
        }
    }

    # Add enrichment data
    if ($enrichedEvent.HostMetadata) {
        $splunkEvent.event.HostMetadata = $enrichedEvent.HostMetadata
    }
    if ($enrichedEvent.ADInfo) {
        $splunkEvent.event.ADInfo = $enrichedEvent.ADInfo
    }
    if ($enrichedEvent.ThreatIntel) {
        $splunkEvent.event.ThreatIntel = $enrichedEvent.ThreatIntel
    }

    return $splunkEvent
}

<#
.SYNOPSIS
    Format event for IBM QRadar LEEF format

.PARAMETER Event
    The event to format

.PARAMETER Config
    SIEM configuration
#>
function Format-EventForQradar {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config
    )

    $enrichedEvent = Add-EventEnrichment -Event $Event -Config $Config

    # LEEF format: LEEF:1.0|Vendor|Product|Version|EventID|fields
    $timestamp = if ($Config.Enrichment.NormalizeTimestamps) {
        (Get-Date $enrichedEvent.TimeCreated).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    } else {
        (Get-Date $enrichedEvent.TimeCreated).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    }

    $leefFields = @{
        devTime = $timestamp -replace "[^0-9T]" -replace "T", ""
        devTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ"
        src = $enrichedEvent.ComputerName
        usrName = $enrichedEvent.UserName
        dst = $env:COMPUTERNAME
        eventId = $enrichedEvent.Id
        eventName = $enrichedEvent.TaskDisplayName
        severity = Map-QradarSeverity -Severity $enrichedEvent.Severity
        filePath = $enrichedEvent.FilePath
        fileHash = $enrichedEvent.FileHash
        publisher = $enrichedEvent.PublisherName
        ruleName = $enrichedEvent.RuleName
    }

    # Add custom fields for enrichment
    if ($enrichedEvent.HostMetadata) {
        $leefFields['hostOS'] = $enrichedEvent.HostMetadata.OSVersion
        $leefFields['hostArch'] = $enrichedEvent.HostMetadata.Architecture
    }

    # Build LEEF string
    $fieldString = ($leefFields.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$($_.Value -replace '\s+', '%20')"
    }) -join "\t"

    $leefMessage = "LEEF:1.0|Microsoft|AppLocker|1.0|$($enrichedEvent.Id)|$fieldString"

    return @{
        Raw = $leefMessage
        Structured = $leefFields
        Timestamp = $timestamp
    }
}

<#
.SYNOPSIS
    Format event for Syslog RFC5424 format

.PARAMETER Event
    The event to format

.PARAMETER Config
    SIEM configuration
#>
function Format-EventForSyslog {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config
    )

    $enrichedEvent = Add-EventEnrichment -Event $Event -Config $Config

    $timestamp = if ($Config.Enrichment.NormalizeTimestamps) {
        (Get-Date $enrichedEvent.TimeCreated).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    } else {
        (Get-Date $enrichedEvent.TimeCreated).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    }

    $severity = Map-SyslogSeverity -Severity $enrichedEvent.Severity
    $facility = 16  # local use 0
    $priority = $facility * 8 + $severity

    # RFC5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    $syslogMessage = "<$priority>1 $timestamp $($enrichedEvent.ComputerName) AppLocker $($enrichedEvent.ProcessId) - -"

    # Add structured data
    $sdFields = @{
        eventId = $enrichedEvent.Id
        userName = $enrichedEvent.UserName
        filePath = $enrichedEvent.FilePath
        publisher = $enrichedEvent.PublisherName
        ruleName = $enrichedEvent.RuleName
    }

    $sdString = ($sdFields.GetEnumerator() | ForEach-Object {
        "$($_.Key)=""$($_.Value)"""
    }) -join " "

    $syslogMessage += " [AppLockerEvents@$($enrichedEvent.ComputerName) $sdString] $($enrichedEvent.Message)"

    return @{
        Raw = $syslogMessage
        Priority = $priority
        Severity = $severity
        Timestamp = $timestamp
    }
}

<#
.SYNOPSIS
    Format event for Elastic/Elasticsearch

.PARAMETER Event
    The event to format

.PARAMETER Config
    SIEM configuration
#>
function Format-EventForElastic {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config
    )

    $enrichedEvent = Add-EventEnrichment -Event $Event -Config $Config

    $timestamp = if ($Config.Enrichment.NormalizeTimestamps) {
        (Get-Date $enrichedEvent.TimeCreated).ToUniversalTime().ToString("o")
    } else {
        (Get-Date $enrichedEvent.TimeCreated).ToString("o")
    }

    $elasticEvent = @{
        "@timestamp" = $timestamp
        event = @{
            module = "applocker"
            dataset = "applocker.events"
            category = "host"
            type = "info"
        }
        host = @{
            name = $enrichedEvent.ComputerName
            hostname = $enrichedEvent.ComputerName
        }
        user = @{
            name = $enrichedEvent.UserName
            id = $enrichedEvent.UserId
        }
        process = @{
            pid = $enrichedEvent.ProcessId
            executable = $enrichedEvent.FilePath
        }
        file = @{
            path = $enrichedEvent.FilePath
            hash = $enrichedEvent.FileHash
        }
        applocker = @{
            event_id = $enrichedEvent.Id
            publisher_name = $enrichedEvent.PublisherName
            rule_name = $enrichedEvent.RuleName
            severity = $enrichedEvent.Severity
        }
        message = $enrichedEvent.Message
    }

    # Add ECS enrichment
    if ($enrichedEvent.HostMetadata) {
        $elasticEvent.host.os = @{
            family = "windows"
            version = $enrichedEvent.HostMetadata.OSVersion
            platform = $enrichedEvent.HostMetadata.OSCaption
        }
        $elasticEvent.host.architecture = $enrichedEvent.HostMetadata.Architecture
    }

    if ($enrichedEvent.ADInfo) {
        $elasticEvent.user.department = $enrichedEvent.ADInfo.Department
        $elasticEvent.user.groups = $enrichedEvent.ADInfo.Groups
    }

    return $elasticEvent
}

<#
.SYNOPSIS
    Format event for custom REST API

.PARAMETER Event
    The event to format

.PARAMETER Config
    SIEM configuration
#>
function Format-EventForRestApi {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config
    )

    $enrichedEvent = Add-EventEnrichment -Event $Event -Config $Config

    $restEvent = @{
        id = $enrichedEvent.Id
        timestamp = if ($Config.Enrichment.NormalizeTimestamps) {
            (Get-Date $enrichedEvent.TimeCreated).ToUniversalTime().ToString("o")
        } else {
            (Get-Date $enrichedEvent.TimeCreated).ToString("o")
        }
        source = "AppLocker"
        source_type = "Windows Event Log"
        host = $enrichedEvent.ComputerName
        event_type = Map-EventType -EventId $enrichedEvent.Id
        severity = $enrichedEvent.Severity
        title = $enrichedEvent.TaskDisplayName
        description = $enrichedEvent.Message
        details = @{
            user = @{
                id = $enrichedEvent.UserId
                name = $enrichedEvent.UserName
            }
            file = @{
                path = $enrichedEvent.FilePath
                hash = $enrichedEvent.FileHash
                publisher = $enrichedEvent.PublisherName
            }
            process = @{
                id = $enrichedEvent.ProcessId
            }
            rule = @{
                name = $enrichedEvent.RuleName
            }
        }
        metadata = @{}
    }

    # Add enrichment
    if ($enrichedEvent.HostMetadata) {
        $restEvent.metadata.host = $enrichedEvent.HostMetadata
    }
    if ($enrichedEvent.ADInfo) {
        $restEvent.metadata.ad = $enrichedEvent.ADInfo
    }
    if ($enrichedEvent.ThreatIntel) {
        $restEvent.metadata.threat_intel = $enrichedEvent.ThreatIntel
    }

    return $restEvent
}

<#
.SYNOPSIS
    Format batch of events for SIEM

.PARAMETER Events
    Array of events

.PARAMETER SiemType
    Target SIEM type

.PARAMETER Config
    SIEM configuration
#>
function Format-BatchForSiem {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Events,

        [Parameter(Mandatory=$true)]
        [string]$SiemType,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    $formattedEvents = switch ($SiemType) {
        "Splunk" {
            $Events | ForEach-Object { Format-EventForSplunk -Event $_ -Config $Config }
        }
        "QRadar" {
            $Events | ForEach-Object { Format-EventForQradar -Event $_ -Config $Config }
        }
        "LogRhythm" {
            # LogRhythm uses similar format to REST API
            $Events | ForEach-Object { Format-EventForRestApi -Event $_ -Config $Config }
        }
        "Elastic" {
            $Events | ForEach-Object { Format-EventForElastic -Event $_ -Config $Config }
        }
        "Syslog" {
            $Events | ForEach-Object { Format-EventForSyslog -Event $_ -Config $Config }
        }
        "RestApi" {
            $Events | ForEach-Object { Format-EventForRestApi -Event $_ -Config $Config }
        }
        default {
            throw "Unsupported SIEM type: $SiemType"
        }
    }

    return @{
        Events = $formattedEvents
        Count = $formattedEvents.Count
        SiemType = $SiemType
    }
}

<#
.SYNOPSIS
    Test SIEM connection

.PARAMETER Config
    SIEM configuration

.EXAMPLE
    Test-SiemConnection
#>
function Test-SiemConnection {
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    Write-SiemLog "Testing SIEM connection to $($Config.Server):$($Config.Port)..." -Level "INFO"

    try {
        $testEvent = @{
            Id = 9999
            TimeCreated = Get-Date
            ComputerName = $env:COMPUTERNAME
            UserName = "SYSTEM"
            UserId = "S-1-5-18"
            ProcessId = $PID
            FilePath = "C:\Windows\System32\test.exe"
            FileHash = "ABC123"
            PublisherName = "Test Publisher"
            RuleName = "Test Rule"
            Severity = "Info"
            Message = "SIEM connection test event"
            LevelDisplayName = "Information"
            TaskDisplayName = "Test"
        }

        $result = Send-SiemEvent -Event $testEvent -Config $Config

        if ($result.Success) {
            Write-SiemLog "Connection test successful!" -Level "INFO"
            return @{ Success = $true; Message = "Connection successful" }
        } else {
            Write-SiemLog "Connection test failed: $($result.Error)" -Level "ERROR"
            return @{ Success = $false; Error = $result.Error }
        }
    } catch {
        Write-SiemLog "Connection test error: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Start the event forwarder background job

.PARAMETER Config
    SIEM configuration
#>
function Start-EventForwarder {
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    if ($script:SiemForwarderJob) {
        Write-SiemLog "Forwarder already running" -Level "WARN"
        return @{ Success = $false; Error = "Forwarder already running" }
    }

    $script:SiemConfig.Enabled = $true
    $script:SiemStatistics.Status = "Running"
    $script:SiemStatistics.StartTime = Get-Date

    Write-SiemLog "Starting SIEM event forwarder..." -Level "INFO"

    # Create background scriptblock
    $forwarderScript = {
        param($ConfigPath, $QueueSize, $BatchSize, $PollInterval)

        # Import config
        if (Test-Path $ConfigPath) {
            $config = Import-Clixml -Path $ConfigPath
        } else {
            return @{ Success = $false; Error = "Config not found" }
        }

        $stats = @{
            Sent = 0
            Failed = 0
            StartTime = Get-Date
            EventsLastMinute = 0
        }

        # Event subscription for new AppLocker events
        $query = "<QueryList><Query Id='0' Path='Microsoft-Windows-AppLocker/EXE and DLL'><Select Path='Microsoft-Windows-AppLocker/EXE and DLL'>*</Select></Query></QueryList>"

        try {
            Register-WmiEvent -Class win32_NTLogEvent -SourceIdentifier "AppLockerSIEMForwarder" `
                -Query $query -MessageData $config -Action {
                    param($event)

                    try {
                        $evt = $event.SourceEventArgs.NewEvent
                        $config = $event.MessageData

                        # Filter event
                        if (-not (Test-EventFilter -Event $evt -Config $config)) {
                            return
                        }

                        # Queue event
                        [void]$script:SiemEventQueue.Enqueue($evt)

                        # Send batch if queue is full
                        if ($script:SiemEventQueue.Count -ge $BatchSize) {
                            $batch = @()
                            while ($batch.Count -lt $BatchSize -and $script:SiemEventQueue.TryDequeue([ref]$evt)) {
                                $batch += $evt
                            }

                            $result = Send-BatchEvents -Events $batch -Config $config
                            if ($result.Success) {
                                $stats.Sent += $result.Sent
                                $stats.EventsLastMinute += $result.Sent
                            } else {
                                $stats.Failed += $result.Failed
                            }
                        }

                        # Calculate events per minute
                        $elapsed = (Get-Date) - $stats.StartTime
                        if ($elapsed.TotalMinutes -gt 0) {
                            $stats.EventsPerMinute = [math]::Round($stats.Sent / $elapsed.TotalMinutes, 2)
                        }

                    } catch {
                        Write-Host "Error processing event: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
        } catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }

        return @{ Success = $true; Stats = $stats }
    }

    # Save config for background job
    $configDir = Split-Path -Parent $script:SiemConfigPath
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    $script:SiemConfig | Export-Clixml -Path $script:SiemConfigPath -Force

    # Start job
    $script:SiemForwarderJob = Start-Job -ScriptBlock $forwarderScript -ArgumentList `
        $script:SiemConfigPath, 1000, $script:SiemConfig.BatchSize, 5

    if ($script:SiemForwarderJob) {
        Write-SiemLog "Event forwarder started (Job ID: $($script:SiemForwarderJob.Id))" -Level "INFO"
        return @{ Success = $true; JobId = $script:SiemForwarderJob.Id }
    } else {
        Write-SiemLog "Failed to start forwarder job" -Level "ERROR"
        return @{ Success = $false; Error = "Failed to start job" }
    }
}

<#
.SYNOPSIS
    Stop the event forwarder

.EXAMPLE
    Stop-EventForwarder
#>
function Stop-EventForwarder {
    if ($script:SiemForwarderJob) {
        Write-SiemLog "Stopping SIEM event forwarder..." -Level "INFO"

        # Unregister event subscription
        Get-EventSubscriber -SourceIdentifier "AppLockerSIEMForwarder" -ErrorAction SilentlyContinue | Unregister-Event

        # Stop job
        Stop-Job -Job $script:SiemForwarderJob
        Remove-Job -Job $script:SiemForwarderJob
        $script:SiemForwarderJob = $null

        $script:SiemConfig.Enabled = $false
        $script:SiemStatistics.Status = "Stopped"

        Write-SiemLog "Event forwarder stopped" -Level "INFO"
        return @{ Success = $true; Message = "Forwarder stopped" }
    } else {
        Write-SiemLog "No forwarder running" -Level "WARN"
        return @{ Success = $false; Error = "No forwarder running" }
    }
}

<#
.SYNOPSIS
    Get forwarding statistics

.EXAMPLE
    Get-ForwarderStatistics
#>
function Get-ForwarderStatistics {
    $stats = $script:SiemStatistics.Clone()

    # Calculate current rate
    if ($stats.StartTime) {
        $elapsed = (Get-Date) - $stats.StartTime
        if ($elapsed.TotalMinutes -gt 0) {
            $stats.EventsPerMinute = [math]::Round($stats.EventsSent / $elapsed.TotalMinutes, 2)
        }
    }

    # Get queue size
    $stats.QueueSize = $script:SiemEventQueue.Count

    return $stats
}

<#
.SYNOPSIS
    Filter event based on configured filters

.PARAMETER Event
    Event to test

.PARAMETER Config
    SIEM configuration with filters
#>
function Test-EventFilter {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    $filters = $Config.Filters

    # Check event type
    $eventType = switch ($Event.Id) {
        8002 { "Allowed" }
        8003 { "Audited" }
        8004 { "Blocked" }
        default { "Other" }
    }

    if ($eventType -eq "Allowed" -and -not $filters.Allowed) { return $false }
    if ($eventType -eq "Blocked" -and -not $filters.Blocked) { return $false }
    if ($eventType -eq "Audited" -and -not $filters.Audited) { return $false }

    # Check severity
    if ($filters.MinSeverity -ne "All") {
        $eventSeverity = Map-EventSeverity -Event $Event
        if (Compare-Severity -Event $eventSeverity -Min $filters.MinSeverity -lt 0) {
            return $false
        }
    }

    # Check include pattern
    if ($filters.IncludePattern) {
        if ($Event.FilePath -notmatch $filters.IncludePattern) {
            return $false
        }
    }

    # Check exclude pattern
    if ($filters.ExcludePattern) {
        if ($Event.FilePath -match $filters.ExcludePattern) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Add enrichment data to event

.PARAMETER Event
    Event to enrich

.PARAMETER Config
    SIEM configuration with enrichment settings
#>
function Add-EventEnrichment {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Event,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    $enrichment = $Config.Enrichment

    # Add basic event properties
    $enrichedEvent = @{
        Id = $Event.Id
        TimeCreated = $Event.TimeCreated
        ComputerName = $Event.MachineName ?? $env:COMPUTERNAME
        Message = $Event.Message
        LevelDisplayName = $Event.LevelDisplayName
        TaskDisplayName = $Event.TaskDisplayName
        ProcessId = $Event.ProcessId
        UserId = $Event.UserId
        UserName = if ($Event.UserId) {
            try {
                $sid = $Event.UserId
                $obj = [System.Security.Principal.SecurityIdentifier]$sid
                $obj.Translate([System.Security.Principal.NTAccount]).Value
            } catch { $Event.UserId }
        } else { "UNKNOWN" }
        Severity = Map-EventSeverity -Event $Event
    }

    # Extract AppLocker-specific data from message
    if ($Event.Message) {
        if ($Event.Message -match 'File path:\s*(.+?)(?:\r|\n)') {
            $enrichedEvent.FilePath = $matches[1].Trim()
        }
        if ($Event.Message -match 'File hash:\s*(.+?)(?:\r|\n)') {
            $enrichedEvent.FileHash = $matches[1].Trim()
        }
        if ($Event.Message -match 'Publisher:\s*(.+?)(?:\r|\n)') {
            $enrichedEvent.PublisherName = $matches[1].Trim()
        }
        if ($Event.Message -match 'Rule:\s*(.+?)(?:\r|\n)') {
            $enrichedEvent.RuleName = $matches[1].Trim()
        }
    }

    # Add host metadata
    if ($enrichment.AddHostMetadata) {
        $enrichedEvent.HostMetadata = Get-HostMetadata
    }

    # Add AD info
    if ($enrichment.AddADInfo) {
        $enrichedEvent.ADInfo = Get-ADUserInfo -UserName $enrichedEvent.UserName
    }

    # Add threat intel
    if ($enrichment.AddThreatIntel) {
        $enrichedEvent.ThreatIntel = Get-ThreatIntelContext -FilePath $enrichedEvent.FilePath -Publisher $enrichedEvent.PublisherName
    }

    return $enrichedEvent
}

<#
.SYNOPSIS
    Get host metadata for enrichment

.EXAMPLE
    Get-HostMetadata
#>
function Get-HostMetadata {
    $metadata = @{
        ComputerName = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        OSVersion = $null
        OSCaption = $null
        Architecture = $null
        OSBuild = $null
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $metadata.OSVersion = $os.Version
        $metadata.OSCaption = $os.Caption
        $metadata.OSBuild = $os.BuildNumber
        $metadata.Architecture = $os.OSArchitecture
    } catch {
        # Silently fail if unable to get OS info
    }

    return $metadata
}

<#
.SYNOPSIS
    Get AD user information for enrichment

.PARAMETER UserName
    User name to lookup

.EXAMPLE
    Get-ADUserInfo -UserName "CONTOSO\jdoe"
#>
function Get-ADUserInfo {
    param(
        [Parameter(Mandatory=$false)]
        [string]$UserName
    )

    if (-not $UserName) {
        return $null
    }

    try {
        # Try to get AD user info
        $domain = ($UserName -split '\\')[0]
        $samAccountName = ($UserName -split '\\')[-1]

        $searcher = [DirectoryServices.DirectorySearcher]::new()
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$samAccountName))"
        $searcher.PropertiesToLoad.AddRange(@("department", "title", "manager", "memberOf", "distinguishedName"))
        $result = $searcher.FindOne()

        if ($result) {
            $groups = $result.Properties["memberof"] | ForEach-Object {
                if ($_ -match 'CN=([^,]+)') {
                    $matches[1]
                }
            }

            return @{
                Department = [string]$result.Properties["department"]
                Title = [string]$result.Properties["title"]
                Manager = [string]$result.Properties["manager"]
                Groups = $groups
                DistinguishedName = [string]$result.Properties["distinguishedname"]
            }
        }
    } catch {
        # Silently fail if AD lookup fails
    }

    return $null
}

<#
.SYNOPSIS
    Get threat intelligence context

.PARAMETER FilePath
    File path to check

.PARAMETER Publisher
    Publisher name

.EXAMPLE
    Get-ThreatIntelContext -FilePath "C:\Temp\suspicious.exe"
#>
function Get-ThreatIntelContext {
    param(
        [Parameter(Mandatory=$false)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [string]$Publisher
    )

    $threatIntel = @{
        RiskScore = 0
        RiskLevel = "Low"
        Indicators = @()
        References = @()
    }

    if (-not $FilePath) {
        return $threatIntel
    }

    # Check for suspicious locations
    $suspiciousPaths = @(
        "$env:TEMP\*",
        "$env:USERPROFILE\Downloads\*",
        "$env:APPData\Temp\*",
        "C:\Temp\*",
        "C:\Windows\Temp\*"
    )

    foreach ($pattern in $suspiciousPaths) {
        if ($FilePath -like $pattern) {
            $threatIntel.RiskScore += 20
            $threatIntel.Indicators += "Suspicious execution location"
            break
        }
    }

    # Check for unknown publisher
    if ($Publisher -and $Publisher -match "Unknown|Unsigned") {
        $threatIntel.RiskScore += 30
        $threatIntel.Indicators += "Unknown or unsigned publisher"
    }

    # Determine risk level
    $threatIntel.RiskLevel = switch ($threatIntel.RiskScore) {
        {$_ -ge 70} { "Critical" }
        {$_ -ge 50} { "High" }
        {$_ -ge 30} { "Medium" }
        {$_ -gt 0} { "Low" }
        default { "None" }
    }

    return $threatIntel
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

<#
.SYNOPSIS
    Send event via HTTP/HTTPS

.PARAMETER FormattedEvent
    The formatted event

.PARAMETER Config
    SIEM configuration
#>
function Send-HttpEvent {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FormattedEvent,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    try {
        $baseUrl = "$($Config.Protocol)://$($Config.Server):$($Config.Port)"
        $endpoint = switch ($Config.SiemType) {
            "Splunk"   { "/services/collector/event" }
            "Elastic"  { "/applocker-events/_doc" }
            "RestApi"  { "/api/events" }
            default    { "/api/events" }
        }

        $url = $baseUrl + $endpoint

        # Build request
        $headers = @{
            "Content-Type" = "application/json"
        }

        # Add authentication
        if ($Config.AuthType -eq "Token") {
            if ($Config.SiemType -eq "Splunk") {
                $headers["Authorization"] = "Splunk $($Config.Token)"
            } else {
                $headers["Authorization"] = "Bearer $($Config.Token)"
            }
        } elseif ($Config.AuthType -eq "Username") {
            $encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Config.Username):$($Config.Password)"))
            $headers["Authorization"] = "Basic $encodedCreds"
        }

        # Convert event to JSON
        $body = switch ($Config.SiemType) {
            "Splunk" { $FormattedEvent | ConvertTo-Json -Depth 10 -Compress }
            default  { $FormattedEvent | ConvertTo-Json -Depth 10 }
        }

        # Send request
        $params = @{
            Uri         = $url
            Method      = "POST"
            Headers     = $headers
            Body        = $body
            TimeoutSec  = 30
        }

        if (-not $Config.UseSSL) {
            $params.SkipCertificateCheck = $true
        }

        $response = Invoke-RestMethod @params -ErrorAction Stop

        return @{ Success = $true; Response = $response }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Send batch via HTTP/HTTPS

.PARAMETER FormattedBatch
    The formatted batch

.PARAMETER Config
    SIEM configuration
#>
function Send-HttpBatch {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FormattedBatch,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    try {
        $baseUrl = "$($Config.Protocol)://$($Config.Server):$($Config.Port)"

        $endpoint = switch ($Config.SiemType) {
            "Splunk"   { "/services/collector/event" }
            "Elastic"  { "/applocker-events/_bulk" }
            default    { "/api/events/batch" }
        }

        $url = $baseUrl + $endpoint

        $headers = @{
            "Content-Type" = "application/json"
        }

        if ($Config.AuthType -eq "Token") {
            if ($Config.SiemType -eq "Splunk") {
                $headers["Authorization"] = "Splunk $($Config.Token)"
            } else {
                $headers["Authorization"] = "Bearer $($Config.Token)"
            }
        } elseif ($Config.AuthType -eq "Username") {
            $encodedCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Config.Username):$($Config.Password)"))
            $headers["Authorization"] = "Basic $encodedCreds"
        }

        # Build batch body
        $body = switch ($Config.SiemType) {
            "Splunk" {
                # Splunk doesn't support true batching, send as array
                (@($FormattedBatch.Events) | ConvertTo-Json -Depth 10 -Compress)
            }
            "Elastic" {
                # Elasticsearch bulk format
                $bulkLines = foreach ($evt in $FormattedBatch.Events) {
                    '{"index": {}}'
                    ($evt | ConvertTo-Json -Depth 10 -Compress)
                }
                $bulkLines -join "`n"
            }
            default {
                (@($FormattedBatch.Events) | ConvertTo-Json -Depth 10)
            }
        }

        $params = @{
            Uri         = $url
            Method      = "POST"
            Headers     = $headers
            Body        = $body
            TimeoutSec  = 60
        }

        if (-not $Config.UseSSL) {
            $params.SkipCertificateCheck = $true
        }

        $response = Invoke-RestMethod @params -ErrorAction Stop

        return @{ Success = $true; Sent = $FormattedBatch.Count; Response = $response }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Send event via TCP

.PARAMETER FormattedEvent
    The formatted event

.PARAMETER Config
    SIEM configuration
#>
function Send-TcpEvent {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FormattedEvent,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect($Config.Server, $Config.Port)

        $stream = $client.GetStream()
        $writer = [System.IO.StreamWriter]::new($stream)
        $data = if ($FormattedEvent.Raw) { $FormattedEvent.Raw } else { ($FormattedEvent | ConvertTo-Json) }

        $writer.WriteLine($data)
        $writer.Flush()
        $writer.Close()

        return @{ Success = $true }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
    finally {
        if ($client) {
            $client.Close()
        }
    }
}

<#
.SYNOPSIS
    Send event via UDP

.PARAMETER FormattedEvent
    The formatted event

.PARAMETER Config
    SIEM configuration
#>
function Send-UdpEvent {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$FormattedEvent,

        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    try {
        $client = [System.Net.Sockets.UdpClient]::new()
        $data = if ($FormattedEvent.Raw) {
            [System.Text.Encoding]::UTF8.GetBytes($FormattedEvent.Raw)
        } else {
            [System.Text.Encoding]::UTF8.GetBytes(($FormattedEvent | ConvertTo-Json))
        }

        $client.Send($data, $data.Length, $Config.Server, $Config.Port)
        $client.Close()

        return @{ Success = $true }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Map event severity

.PARAMETER Event
    Event object
#>
function Map-EventSeverity {
    param([object]$Event)

    return switch ($Event.Id) {
        8004 { "Critical" }  # Blocked
        8003 { "Warning" }   # Audited
        8002 { "Info" }      # Allowed
        default { "Info" }
    }
}

<#
.SYNOPSIS
    Map severity to QRadar format

.PARAMETER Severity
    Severity level
#>
function Map-QradarSeverity {
    param([string]$Severity)

    return switch ($Severity) {
        "Critical" { 10 }
        "High"     { 8 }
        "Error"    { 7 }
        "Warning"  { 5 }
        "Medium"   { 4 }
        "Info"     { 1 }
        default    { 1 }
    }
}

<#
.SYNOPSIS
    Map severity to Syslog format

.PARAMETER Severity
    Severity level
#>
function Map-SyslogSeverity {
    param([string]$Severity)

    return switch ($Severity) {
        "Critical" { 2 }  # Critical
        "High"     { 2 }
        "Error"    { 3 }  # Error
        "Warning"  { 4 }  # Warning
        "Medium"   { 5 }  # Notice
        "Info"     { 6 }  # Informational
        default    { 6 }
    }
}

<#
.SYNOPSIS
    Compare severity levels

.PARAMETER Event
    Event severity

.PARAMETER Min
    Minimum severity

.PARAMETER Operator
    Comparison operator (default: -lt)
#>
function Compare-Severity {
    param(
        [string]$Event,
        [string]$Min,
        [string]$Operator = "-lt"
    )

    $levels = @{
        "Info"     = 1
        "Warning"  = 2
        "Error"    = 3
        "High"     = 4
        "Critical" = 5
        "All"      = 0
    }

    $eventLevel = if ($levels.ContainsKey($Event)) { $levels[$Event] } else { 0 }
    $minLevel = if ($levels.ContainsKey($Min)) { $levels[$Min] } else { 0 }

    switch ($Operator) {
        "-lt" { return $eventLevel -lt $minLevel }
        "-le" { return $eventLevel -le $minLevel }
        "-gt" { return $eventLevel -gt $minLevel }
        "-ge" { return $eventLevel -ge $minLevel }
        default { return $eventLevel -lt $minLevel }
    }
}

<#
.SYNOPSIS
    Map AppLocker event ID to type

.PARAMETER EventId
    AppLocker event ID
#>
function Map-EventType {
    param([int]$EventId)

    return switch ($EventId) {
        8002 { "Allow" }
        8003 { "Audit" }
        8004 { "Block" }
        default { "Unknown" }
    }
}

<#
.SYNOPSIS
    Write to SIEM log

.PARAMETER Message
    Log message

.PARAMETER Level
    Log level (INFO, WARN, ERROR)

.EXAMPLE
    Write-SiemLog "Connection successful" -Level "INFO"
#>
function Write-SiemLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"  { "Green" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "DEBUG" { "Cyan" }
    }

    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to host if in console
    if ($Host.UI.RawUI.ForegroundColor) {
        Write-Host $logEntry -ForegroundColor $color
    } else {
        Write-Host $logEntry
    }

    # Store in memory for GUI access
    if (-not $script:SiemLogBuffer) {
        $script:SiemLogBuffer = [System.Collections.Generic.List[string]]::new()
    }
    $script:SiemLogBuffer.Add($logEntry)
    if ($script:SiemLogBuffer.Count -gt 1000) {
        $script:SiemLogBuffer.RemoveAt(0)
    }

    # Append to log file if configured
    $logFile = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Integration.log"
    $logDir = Split-Path -Parent $logFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
    Save SIEM configuration to encrypted file

.PARAMETER ConfigPath
    Path to save configuration

.PARAMETER Config
    Configuration to save

.EXAMPLE
    Save-SiemConfig
#>
function Save-SiemConfig {
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigPath = $script:SiemConfigPath,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    try {
        $configDir = Split-Path -Parent $ConfigPath
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }

        # Create a copy of config without sensitive data for export
        $configToSave = $Config.Clone()

        # Encrypt sensitive data
        if ($configToSave.Token) {
            $secureString = ConvertTo-SecureString -String $configToSave.Token -AsPlainText -Force
            $configToSave.Token = ConvertFrom-SecureString -SecureString $secureString
        }

        if ($configToSave.Password) {
            $secureString = ConvertTo-SecureString -String $configToSave.Password -AsPlainText -Force
            $configToSave.Password = ConvertFrom-SecureString -SecureString $secureString
        }

        $configToSave | Export-Clixml -Path $ConfigPath -Force

        Write-SiemLog "Configuration saved to $ConfigPath" -Level "INFO"
        return @{ Success = $true; Path = $ConfigPath }
    } catch {
        Write-SiemLog "Failed to save configuration: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Load SIEM configuration from encrypted file

.PARAMETER ConfigPath
    Path to configuration file

.EXAMPLE
    Load-SiemConfig
#>
function Load-SiemConfig {
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigPath = $script:SiemConfigPath
    )

    try {
        if (-not (Test-Path $ConfigPath)) {
            return @{ Success = $false; Error = "Configuration file not found" }
        }

        $config = Import-Clixml -Path $ConfigPath

        # Decrypt sensitive data
        if ($config.Token -is [string]) {
            try {
                $secureString = ConvertTo-SecureString -String $config.Token
                $config.Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
            } catch {
                # Token might already be decrypted or invalid
            }
        }

        if ($config.Password -is [string]) {
            try {
                $secureString = ConvertTo-SecureString -String $config.Password
                $config.Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
            } catch {
                # Password might already be decrypted or invalid
            }
        }

        # Update global config
        foreach ($key in $config.Keys) {
            $script:SiemConfig[$key] = $config[$key]
        }

        Write-SiemLog "Configuration loaded from $ConfigPath" -Level "INFO"
        return @{ Success = $true; Config = $config }
    } catch {
        Write-SiemLog "Failed to load configuration: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

<#
.SYNOPSIS
    Get available SIEM configuration profiles

.EXAMPLE
    Get-SiemProfiles
#>
function Get-SiemProfiles {
    $profileDir = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Profiles"

    if (-not (Test-Path $profileDir)) {
        return @()
    }

    $profiles = Get-ChildItem -Path $profileDir -Filter "*.xml" | ForEach-Object {
        @{
            Name = $_.BaseName
            Path = $_.FullName
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
        }
    }

    return $profiles
}

<#
.SYNOPSIS
    Save SIEM configuration as a named profile

.PARAMETER ProfileName
    Name for the profile

.PARAMETER Config
    Configuration to save

.EXAMPLE
    Save-SiemProfile -ProfileName "Production-Splunk"
#>
function Save-SiemProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,

        [Parameter(Mandatory=$false)]
        [hashtable]$Config = $script:SiemConfig
    )

    $profileDir = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Profiles"
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }

    # Sanitize profile name
    $ProfileName = $ProfileName -replace '[^a-zA-Z0-9\-_]', '_'
    $profilePath = Join-Path $profileDir "$ProfileName.xml"

    return Save-SiemConfig -ConfigPath $profilePath -Config $Config
}

<#
.SYNOPSIS
    Load SIEM configuration from a named profile

.PARAMETER ProfileName
    Name of the profile to load

.EXAMPLE
    Load-SiemProfile -ProfileName "Production-Splunk"
#>
function Load-SiemProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName
    )

    $profilePath = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Profiles\$ProfileName.xml"

    return Load-SiemConfig -ConfigPath $profilePath
}

<#
.SYNOPSIS
    Delete a SIEM configuration profile

.PARAMETER ProfileName
    Name of the profile to delete

.EXAMPLE
    Remove-SiemProfile -ProfileName "Old-Config"
#>
function Remove-SiemProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName
    )

    $profilePath = "$env:LOCALAPPDATA\GA-AppLocker\SIEM-Profiles\$ProfileName.xml"

    try {
        if (Test-Path $profilePath) {
            Remove-Item -Path $profilePath -Force
            Write-SiemLog "Profile '$ProfileName' deleted" -Level "INFO"
            return @{ Success = $true }
        } else {
            return @{ Success = $false; Error = "Profile not found" }
        }
    } catch {
        Write-SiemLog "Failed to delete profile: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Send-SiemEvent',
    'Send-BatchEvents',
    'Format-EventForSplunk',
    'Format-EventForQradar',
    'Format-EventForSyslog',
    'Format-EventForElastic',
    'Format-EventForRestApi',
    'Test-SiemConnection',
    'Start-EventForwarder',
    'Stop-EventForwarder',
    'Get-ForwarderStatistics',
    'Save-SiemConfig',
    'Load-SiemConfig',
    'Get-SiemProfiles',
    'Save-SiemProfile',
    'Load-SiemProfile',
    'Remove-SiemProfile',
    'Write-SiemLog'
)
