<#
.SYNOPSIS
    Continuous AppLocker event monitoring with scheduled collection.

.DESCRIPTION
    Runs as a background monitoring service that periodically collects AppLocker
    audit events from specified computers. Supports:
    - Configurable collection intervals
    - Email/webhook alerts for new blocked apps
    - Automatic rule suggestion generation
    - Rolling log retention
    - Dashboard-ready JSON output

.PARAMETER ComputerListPath
    Path to file containing target computer names.

.PARAMETER OutputPath
    Directory for monitoring data and reports.

.PARAMETER IntervalMinutes
    Collection interval in minutes (default: 60).

.PARAMETER RetentionDays
    Days to retain historical data (default: 30).

.PARAMETER AlertThreshold
    Number of new blocked apps that triggers an alert (default: 5).

.PARAMETER AlertWebhook
    Webhook URL for sending alerts (Teams, Slack, etc.).

.PARAMETER AlertEmail
    Email address for sending alerts (requires SMTP config).

.PARAMETER AsJob
    Run as a background job.

.PARAMETER MaxRuns
    Maximum collection runs before stopping (0 = unlimited).

.EXAMPLE
    .\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -IntervalMinutes 30

.EXAMPLE
    .\Start-AppLockerMonitor.ps1 -ComputerListPath .\computers.txt -AsJob -AlertWebhook "https://..."

.NOTES
    To stop monitoring: Get-Job -Name "AppLockerMonitor" | Stop-Job
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ComputerListPath,

    [string]$OutputPath = '.\Monitoring',

    [ValidateRange(5, 1440)]
    [int]$IntervalMinutes = 60,

    [ValidateRange(1, 365)]
    [int]$RetentionDays = 30,

    [int]$AlertThreshold = 5,

    [string]$AlertWebhook,

    [string]$AlertEmail,

    [string]$SmtpServer,

    [PSCredential]$Credential,

    [switch]$AsJob,

    [int]$MaxRuns = 0,

    [switch]$IncludeAllowedEvents
)

$ErrorActionPreference = 'Stop'

# Get module root for imports
$scriptRoot = Split-Path $PSScriptRoot -Parent

# Import common functions and error handling
Import-Module (Join-Path $scriptRoot 'utilities\Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ErrorHandling.psm1') -Force

#region Helper Functions

function Write-MonitorLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    $color = switch ($Level) {
        'Info' { 'Gray' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host $logEntry -ForegroundColor $color

    # Also write to log file
    $logFile = Join-Path $Script:MonitoringPath 'monitor.log'
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Send-MonitorAlert {
    param(
        [string]$Title,
        [string]$Message,
        [array]$BlockedApps
    )

    # Create alert payload
    $alertData = @{
        Title = $Title
        Message = $Message
        Timestamp = Get-Date -Format 'o'
        NewBlockedApps = $BlockedApps.Count
        TopApps = $BlockedApps | Select-Object -First 10 | ForEach-Object {
            @{
                Path = $_.Path
                Publisher = $_.Publisher
                Count = $_.Count
                Computers = $_.AffectedComputers -join ', '
            }
        }
    }

    # Send to webhook if configured
    if ($Script:AlertWebhook) {
        try {
            # Format for Microsoft Teams
            $teamsPayload = @{
                '@type' = 'MessageCard'
                '@context' = 'http://schema.org/extensions'
                'themeColor' = 'FF6600'
                'summary' = $Title
                'sections' = @(
                    @{
                        'activityTitle' = $Title
                        'activitySubtitle' = $Message
                        'facts' = @(
                            @{ 'name' = 'New Blocked Apps'; 'value' = $BlockedApps.Count.ToString() }
                            @{ 'name' = 'Time'; 'value' = (Get-Date -Format 'g') }
                        )
                        'markdown' = $true
                    }
                )
            }

            $json = $teamsPayload | ConvertTo-Json -Depth 10
            Invoke-RestMethod -Uri $Script:AlertWebhook -Method Post -Body $json -ContentType 'application/json' | Out-Null
            Write-MonitorLog "Alert sent to webhook" -Level Info
        }
        catch {
            Write-MonitorLog "Failed to send webhook alert: $_" -Level Warning
        }
    }

    # Send email if configured
    if ($Script:AlertEmail -and $Script:SmtpServer) {
        try {
            $body = @"
$Message

New Blocked Applications Detected:
$($BlockedApps | Select-Object -First 20 | ForEach-Object { "- $($_.Path) (Count: $($_.Count))" } | Out-String)

View the full report at: $Script:MonitoringPath

---
GA-AppLocker Monitoring System
"@

            $mailParams = @{
                To = $Script:AlertEmail
                From = "applocker-monitor@$env:USERDNSDOMAIN"
                Subject = "[AppLocker Alert] $Title"
                Body = $body
                SmtpServer = $Script:SmtpServer
            }

            Send-MailMessage @mailParams
            Write-MonitorLog "Alert email sent to $($Script:AlertEmail)" -Level Info
        }
        catch {
            Write-MonitorLog "Failed to send email alert: $_" -Level Warning
        }
    }

    # Save alert to file
    $alertFile = Join-Path $Script:MonitoringPath "alerts\alert-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $alertData | ConvertTo-Json -Depth 10 | Out-File $alertFile -Encoding UTF8
}

function Get-BaselineBlockedApps {
    $baselineFile = Join-Path $Script:MonitoringPath 'baseline-blocked.json'
    if (Test-Path $baselineFile) {
        return Get-Content $baselineFile -Raw | ConvertFrom-Json
    }
    return @()
}

function Update-BaselineBlockedApps {
    param([array]$BlockedApps)

    $baselineFile = Join-Path $Script:MonitoringPath 'baseline-blocked.json'
    $BlockedApps | ConvertTo-Json -Depth 5 | Out-File $baselineFile -Encoding UTF8
}

function Compare-BlockedApps {
    param(
        [array]$Baseline,
        [array]$Current
    )

    $baselinePaths = $Baseline | ForEach-Object { $_.Path }
    $newApps = $Current | Where-Object { $_.Path -notin $baselinePaths }

    return $newApps
}

function Invoke-DataRetention {
    param([int]$RetentionDays)

    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)

    # Clean old collection folders
    $collectionsPath = Join-Path $Script:MonitoringPath 'collections'
    if (Test-Path $collectionsPath) {
        Get-ChildItem $collectionsPath -Directory | Where-Object {
            $_.CreationTime -lt $cutoffDate
        } | ForEach-Object {
            Write-MonitorLog "Removing old collection: $($_.Name)" -Level Info
            Remove-Item $_.FullName -Recurse -Force
        }
    }

    # Clean old alerts
    $alertsPath = Join-Path $Script:MonitoringPath 'alerts'
    if (Test-Path $alertsPath) {
        Get-ChildItem $alertsPath -File | Where-Object {
            $_.CreationTime -lt $cutoffDate
        } | ForEach-Object {
            Remove-Item $_.FullName -Force
        }
    }

    # Trim log file
    $logFile = Join-Path $Script:MonitoringPath 'monitor.log'
    if (Test-Path $logFile) {
        $logContent = Get-Content $logFile -Tail 10000
        $logContent | Out-File $logFile -Encoding UTF8
    }
}

function Export-MonitoringDashboard {
    param([array]$CurrentData)

    $dashboardFile = Join-Path $Script:MonitoringPath 'dashboard.json'

    # Load historical data
    $historicalFile = Join-Path $Script:MonitoringPath 'historical-stats.json'
    $historical = @()
    if (Test-Path $historicalFile) {
        $historical = Get-Content $historicalFile -Raw | ConvertFrom-Json
    }

    # Add current stats
    $currentStats = @{
        Timestamp = Get-Date -Format 'o'
        TotalBlocked = $CurrentData.Count
        UniqueApps = ($CurrentData | Select-Object -ExpandProperty Path -Unique).Count
        TopPublisher = ($CurrentData | Group-Object Publisher | Sort-Object Count -Descending | Select-Object -First 1).Name
    }

    $historical += $currentStats

    # Keep last 30 days of hourly stats
    $cutoff = (Get-Date).AddDays(-30)
    $historical = $historical | Where-Object {
        [datetime]$_.Timestamp -gt $cutoff
    }

    $historical | ConvertTo-Json -Depth 5 | Out-File $historicalFile -Encoding UTF8

    # Create dashboard summary
    $dashboard = @{
        LastUpdated = Get-Date -Format 'o'
        Status = 'Running'
        CollectionInterval = "$($Script:IntervalMinutes) minutes"
        TotalCollections = ($historical | Measure-Object).Count
        CurrentBlocked = @{
            Total = $CurrentData.Count
            UniqueApps = ($CurrentData | Select-Object -ExpandProperty Path -Unique).Count
            ByCollection = $CurrentData | Group-Object Collection | ForEach-Object {
                @{ Collection = $_.Name; Count = $_.Count }
            }
        }
        TopBlockedApps = $CurrentData | Group-Object Path |
            Sort-Object Count -Descending |
            Select-Object -First 20 |
            ForEach-Object {
                @{
                    Path = $_.Name
                    Count = $_.Count
                    LastSeen = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                }
            }
        TrendData = $historical | Select-Object -Last 24
    }

    $dashboard | ConvertTo-Json -Depth 10 | Out-File $dashboardFile -Encoding UTF8

    return $dashboard
}

#endregion

#region Main Monitoring Loop

$monitoringScript = {
    param(
        $ComputerListPath,
        $OutputPath,
        $IntervalMinutes,
        $RetentionDays,
        $AlertThreshold,
        $AlertWebhook,
        $AlertEmail,
        $SmtpServer,
        $Credential,
        $MaxRuns,
        $IncludeAllowedEvents,
        $ScriptRoot
    )

    # Store in script scope for helper functions
    $Script:MonitoringPath = $OutputPath
    $Script:IntervalMinutes = $IntervalMinutes
    $Script:AlertWebhook = $AlertWebhook
    $Script:AlertEmail = $AlertEmail
    $Script:SmtpServer = $SmtpServer

    # Ensure directories exist
    @('collections', 'alerts', 'reports') | ForEach-Object {
        $dir = Join-Path $OutputPath $_
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Import modules
    Import-Module (Join-Path $ScriptRoot 'utilities\Common.psm1') -Force

    $runCount = 0
    $startTime = Get-Date

    Write-MonitorLog "AppLocker Monitor started" -Level Success
    Write-MonitorLog "  Computers: $ComputerListPath" -Level Info
    Write-MonitorLog "  Interval: $IntervalMinutes minutes" -Level Info
    Write-MonitorLog "  Retention: $RetentionDays days" -Level Info

    while ($true) {
        $runCount++
        $collectionStart = Get-Date

        Write-MonitorLog "Starting collection run #$runCount" -Level Info

        try {
            # Create collection output folder
            $collectionFolder = Join-Path $OutputPath "collections\$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            New-Item -ItemType Directory -Path $collectionFolder -Force | Out-Null

            # Run event collection
            $eventParams = @{
                ComputerListPath = $ComputerListPath
                OutputPath = $collectionFolder
                DaysBack = 1  # Only get last day's events each run
                MaxEvents = 10000
            }

            if ($Credential) {
                $eventParams.Credential = $Credential
            }

            if ($IncludeAllowedEvents) {
                $eventParams.IncludeAllowedEvents = $true
            }

            $eventScript = Join-Path $ScriptRoot 'Invoke-RemoteEventCollection.ps1'
            & $eventScript @eventParams

            # Load and analyze results
            $allBlockedFile = Join-Path $collectionFolder 'AllBlockedEvents.csv'
            if (Test-Path $allBlockedFile) {
                $currentBlocked = Import-Csv $allBlockedFile

                Write-MonitorLog "Collected $($currentBlocked.Count) blocked events" -Level Info

                # Compare with baseline
                $baseline = Get-BaselineBlockedApps
                $newApps = Compare-BlockedApps -Baseline $baseline -Current $currentBlocked

                if ($newApps.Count -gt 0) {
                    Write-MonitorLog "Detected $($newApps.Count) NEW blocked applications" -Level Warning

                    # Generate suggested rules for new apps
                    $suggestionsFile = Join-Path $collectionFolder 'suggested-rules.txt'
                    $suggestions = $newApps | ForEach-Object {
                        if ($_.Publisher -and $_.Publisher -ne 'Unknown') {
                            "# Publisher rule for: $($_.Path)`nPublisher: $($_.Publisher)"
                        } else {
                            "# Path rule for: $($_.Path)`nPath: $($_.Path)"
                        }
                    }
                    $suggestions | Out-File $suggestionsFile -Encoding UTF8

                    # Check if alert threshold exceeded
                    if ($newApps.Count -ge $AlertThreshold) {
                        Send-MonitorAlert -Title "New Blocked Applications Detected" `
                            -Message "$($newApps.Count) new applications were blocked since last collection." `
                            -BlockedApps $newApps
                    }

                    # Update baseline with all current apps
                    Update-BaselineBlockedApps -BlockedApps $currentBlocked
                }

                # Export dashboard data
                $dashboard = Export-MonitoringDashboard -CurrentData $currentBlocked
                Write-MonitorLog "Dashboard updated: $($dashboard.CurrentBlocked.Total) blocked apps tracked" -Level Info
            }

            # Run data retention cleanup
            Invoke-DataRetention -RetentionDays $RetentionDays

            $collectionDuration = (Get-Date) - $collectionStart
            Write-MonitorLog "Collection completed in $([math]::Round($collectionDuration.TotalSeconds, 1)) seconds" -Level Success
        }
        catch {
            Write-MonitorLog "Collection error: $_" -Level Error
        }

        # Check if we should stop
        if ($MaxRuns -gt 0 -and $runCount -ge $MaxRuns) {
            Write-MonitorLog "Reached maximum runs ($MaxRuns). Stopping monitor." -Level Info
            break
        }

        # Wait for next interval
        $nextRun = $collectionStart.AddMinutes($IntervalMinutes)
        $waitTime = $nextRun - (Get-Date)

        if ($waitTime.TotalSeconds -gt 0) {
            Write-MonitorLog "Next collection at $($nextRun.ToString('HH:mm:ss'))" -Level Info
            Start-Sleep -Seconds $waitTime.TotalSeconds
        }
    }

    Write-MonitorLog "AppLocker Monitor stopped" -Level Info
}

#endregion

#region Entry Point

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Validate computer list using standardized validation
$validComputerList = Test-ValidPath -Path $ComputerListPath -Type File -MustExist
if (-not $validComputerList) {
    Write-ErrorMessage -Message "Computer list not found: $ComputerListPath" -Throw
}

Write-SectionHeader -Title "GA-AppLocker Monitoring System"

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Computer List:     $ComputerListPath" -ForegroundColor Gray
Write-Host "  Output Path:       $OutputPath" -ForegroundColor Gray
Write-Host "  Interval:          $IntervalMinutes minutes" -ForegroundColor Gray
Write-Host "  Retention:         $RetentionDays days" -ForegroundColor Gray
Write-Host "  Alert Threshold:   $AlertThreshold new apps" -ForegroundColor Gray
Write-Host "  Webhook:           $(if ($AlertWebhook) { 'Configured' } else { 'Not set' })" -ForegroundColor Gray
Write-Host "  Email Alerts:      $(if ($AlertEmail) { $AlertEmail } else { 'Not set' })" -ForegroundColor Gray
Write-Host ""

if ($AsJob) {
    Write-Host "Starting monitor as background job..." -ForegroundColor Yellow

    $jobParams = @{
        ComputerListPath = $ComputerListPath
        OutputPath = $OutputPath
        IntervalMinutes = $IntervalMinutes
        RetentionDays = $RetentionDays
        AlertThreshold = $AlertThreshold
        AlertWebhook = $AlertWebhook
        AlertEmail = $AlertEmail
        SmtpServer = $SmtpServer
        Credential = $Credential
        MaxRuns = $MaxRuns
        IncludeAllowedEvents = $IncludeAllowedEvents
        ScriptRoot = $scriptRoot
    }

    $job = Start-Job -Name "AppLockerMonitor" -ScriptBlock $monitoringScript -ArgumentList @(
        $jobParams.ComputerListPath,
        $jobParams.OutputPath,
        $jobParams.IntervalMinutes,
        $jobParams.RetentionDays,
        $jobParams.AlertThreshold,
        $jobParams.AlertWebhook,
        $jobParams.AlertEmail,
        $jobParams.SmtpServer,
        $jobParams.Credential,
        $jobParams.MaxRuns,
        $jobParams.IncludeAllowedEvents,
        $jobParams.ScriptRoot
    )

    Write-Host "Monitor started as job: $($job.Name) (ID: $($job.Id))" -ForegroundColor Green
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  View status:    Get-Job -Name 'AppLockerMonitor'" -ForegroundColor Gray
    Write-Host "  View output:    Receive-Job -Name 'AppLockerMonitor'" -ForegroundColor Gray
    Write-Host "  Stop monitor:   Stop-Job -Name 'AppLockerMonitor'" -ForegroundColor Gray
    Write-Host "  Dashboard:      Get-Content '$OutputPath\dashboard.json'" -ForegroundColor Gray
    Write-Host ""

    return $job
} else {
    Write-Host "Starting monitor in foreground (Ctrl+C to stop)..." -ForegroundColor Yellow
    Write-Host ""

    # Run directly
    & $monitoringScript -ComputerListPath $ComputerListPath `
        -OutputPath $OutputPath `
        -IntervalMinutes $IntervalMinutes `
        -RetentionDays $RetentionDays `
        -AlertThreshold $AlertThreshold `
        -AlertWebhook $AlertWebhook `
        -AlertEmail $AlertEmail `
        -SmtpServer $SmtpServer `
        -Credential $Credential `
        -MaxRuns $MaxRuns `
        -IncludeAllowedEvents $IncludeAllowedEvents `
        -ScriptRoot $scriptRoot
}

#endregion
