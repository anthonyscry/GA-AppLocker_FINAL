<#
.SYNOPSIS
    Remotely collects AppLocker audit events from target computers for rule creation.

.DESCRIPTION
    Part of GA-AppLocker toolkit. Use Start-AppLockerWorkflow.ps1 for guided experience.

    This script connects to remote computers via WinRM and collects AppLocker audit
    events from the Windows Event Log. These events are generated when AppLocker is
    running in Audit mode and records what would have been allowed or blocked.

    Event IDs Collected:
    - 8003: Would have been allowed (EXE and DLL)
    - 8004: Would have been blocked (EXE and DLL)
    - 8005: Would have been allowed (MSI and Script)
    - 8006: Would have been blocked (MSI and Script)
    - 8007: Would have been allowed (Packaged app)
    - 8008: Would have been blocked (Packaged app)

    The collected data can be used to:
    - Identify applications that need allow rules before enforcing policies
    - Create rules from blocked events to whitelist legitimate software
    - Analyze what's running in your environment during audit period
    - Generate policies based on real-world application usage

    Key Features:
    - Parallel processing with configurable throttle limit
    - Extracts publisher and hash information for rule generation
    - Exports data compatible with policy generation scripts
    - Filters by date range to focus on recent events
    - Supports filtering blocked-only events for targeted rule creation

.PARAMETER ComputerListPath
    Path to a text file containing one computer name per line.
    Empty lines and lines starting with # are ignored.

.PARAMETER OutputPath
    Path to save collected results.
    A timestamped subfolder will be created automatically.

.PARAMETER Credential
    Credential for remote connections (DOMAIN\username format).
    If not provided, prompts interactively.

.PARAMETER ThrottleLimit
    Maximum concurrent connections (default: 10).

.PARAMETER DaysBack
    Number of days of events to collect (default: 14).
    Set to 0 for all available events.

.PARAMETER BlockedOnly
    Only collect "would have been blocked" events (8004, 8006, 8008).
    Useful for creating rules for software that needs to be whitelisted.

.PARAMETER IncludeAllowedEvents
    Also collect "would have been allowed" events (8003, 8005, 8007).
    Useful for auditing what's currently allowed by policy.

.PARAMETER MaxEventsPerComputer
    Maximum events to collect per computer (default: 5000).
    Prevents overwhelming systems with large event logs.

.PARAMETER SinceLastRun
    Only collect events since the last successful collection.
    Stores timestamp in .\Events\.lastrun file for incremental collection.
    Useful for continuous monitoring to avoid re-collecting old events.

.PARAMETER StateFilePath
    Custom path for the state file that tracks last run timestamp.
    Default: .\Events\.lastrun

.EXAMPLE
    # Collect blocked events from last 14 days
    .\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\ADManagement\computers.csv -OutputPath .\Events

.EXAMPLE
    # Collect all audit events from last 30 days
    .\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\ADManagement\computers.csv -OutputPath .\Events -DaysBack 30 -IncludeAllowedEvents

.EXAMPLE
    # Collect only blocked events (for rule creation)
    .\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\ADManagement\computers.csv -OutputPath .\Events -BlockedOnly

.EXAMPLE
    # Incremental collection - only get events since last run
    .\Invoke-RemoteEventCollection.ps1 -ComputerListPath .\ADManagement\computers.csv -OutputPath .\Events -SinceLastRun

.NOTES
    Requires: PowerShell 5.1+
    Requires: WinRM enabled on target computers
    Requires: Admin credentials with remote access
    Requires: AppLocker running in Audit mode on targets

    Output Structure:
    ├── Events-{timestamp}/
    │   ├── EventCollectionResults.csv    (summary log)
    │   ├── AllBlockedEvents.csv          (consolidated blocked events)
    │   ├── UniqueBlockedApps.csv         (deduplicated for rule creation)
    │   ├── COMPUTER1/
    │   │   ├── BlockedEvents.csv         (8004, 8006, 8008 events)
    │   │   ├── AllowedEvents.csv         (8003, 8005, 8007 if requested)
    │   │   └── EventSummary.csv          (counts by type)
    │   └── COMPUTER2/
    │       └── ...

    Event Log Path: Microsoft-Windows-AppLocker/EXE and DLL
                    Microsoft-Windows-AppLocker/MSI and Script
                    Microsoft-Windows-AppLocker/Packaged app-Execution

    Author: GA-AppLocker Toolkit
    Version: 1.0
#>

[CmdletBinding(DefaultParameterSetName='Standard')]
param(
    [Parameter(Position=0,
        HelpMessage="Path to file containing computer names (TXT or CSV with ComputerName column)")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "Computer list file not found: $_"
        }
        $ext = [System.IO.Path]::GetExtension($_).ToLower()
        if ($ext -notin '.txt', '.csv') {
            throw "Computer list must be a .txt or .csv file"
        }
        $true
    })]
    [string]$ComputerListPath = ".\ADManagement\computers.csv",

    [Parameter(Position=1,
        HelpMessage="Path to save event collection results")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        # Allow path to be created if parent exists
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "Parent directory does not exist: $parent"
        }
        $true
    })]
    [string]$OutputPath = ".\Events",

    [Parameter(HelpMessage="Credentials for remote connections (DOMAIN\username)")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential,

    [Parameter(HelpMessage="Separate credentials for Domain Controllers (DOMAIN\username)")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $DCCredential,

    [Parameter(HelpMessage="Maximum concurrent remote connections (1-100)")]
    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = 10,

    [Parameter(HelpMessage="Days of events to collect (0 for all available)")]
    [ValidateRange(0, 365)]
    [int]$DaysBack = 14,

    [Parameter(HelpMessage="Only collect blocked events (8004, 8006, 8008)")]
    [switch]$BlockedOnly,

    [Parameter(HelpMessage="Also collect allowed events (8003, 8005, 8007)")]
    [switch]$IncludeAllowedEvents,

    [Parameter(HelpMessage="Maximum events to collect per computer")]
    [ValidateRange(100, 50000)]
    [int]$MaxEventsPerComputer = 5000,

    [Parameter(HelpMessage="Only collect events since last successful run (incremental mode)")]
    [switch]$SinceLastRun,

    [Parameter(HelpMessage="Path to state file for tracking last run timestamp")]
    [string]$StateFilePath
)

#Requires -Version 5.1

# Import utilities module
$scriptRoot = $PSScriptRoot
$utilitiesRoot = Join-Path (Split-Path -Parent $scriptRoot) "Utilities"
$modulePath = Join-Path $utilitiesRoot "Common.psm1"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    Write-Warning "Common.psm1 not found at $modulePath - some features may be limited"
}

# Initialize logging
if (Get-Command Start-Logging -ErrorAction SilentlyContinue) {
    Start-Logging -LogName "EventCollection"
    Write-Log "Event collection operation started" -Level Info
    Write-Log "Computer list: $ComputerListPath" -Level Info
    Write-Log "Days back: $(if ($DaysBack -eq 0) { 'All' } else { $DaysBack })" -Level Info
    Write-Log "Event types: $(if ($BlockedOnly) { 'Blocked only' } elseif ($IncludeAllowedEvents) { 'All audit' } else { 'Blocked only' })" -Level Info
}

# Note: Path validation is now handled by ValidateScript in parameter declaration

# Handle incremental collection state
if (-not $StateFilePath) {
    $StateFilePath = Join-Path $OutputPath ".lastrun"
}

$lastRunTime = $null
if ($SinceLastRun) {
    if (Test-Path $StateFilePath) {
        try {
            $stateContent = Get-Content $StateFilePath -Raw | ConvertFrom-Json
            $lastRunTime = [DateTime]::Parse($stateContent.LastSuccessfulRun)
            Write-Host "Incremental mode: Collecting events since $($lastRunTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
            if (Test-LoggingEnabled) {
                Write-Log "Incremental mode: Starting from $($lastRunTime.ToString('o'))" -Level Info
            }
        }
        catch {
            Write-Warning "Could not read state file. Running full collection."
            $lastRunTime = $null
        }
    }
    else {
        Write-Host "No previous run found. Running full collection (will save state for next run)." -ForegroundColor Yellow
    }
}

# Create output directory
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputRoot = Join-Path $OutputPath "Events-$timestamp"
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$outputRoot = (Resolve-Path $outputRoot).Path

# Get credentials if not provided
if ($null -eq $Credential) {
    try {
        $Credential = Get-Credential -Message "Enter credentials for remote connections (DOMAIN\username)"
    }
    catch {
        $errorMsg = "Failed to prompt for credentials: $_"
        if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
        throw $errorMsg
    }
}

if ($null -eq $Credential) {
    $errorMsg = "Credentials are required. Operation cancelled."
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if (Test-LoggingEnabled) {
    Write-Log "Credentials provided for user: $($Credential.UserName)" -Level Info
}

# Load computer list - uses Get-ComputerList from Common.psm1 (supports TXT and CSV)
try {
    if (Get-Command Get-ComputerList -ErrorAction SilentlyContinue) {
        $computers = @(Get-ComputerList -Path $ComputerListPath)
    }
    else {
        # Fallback for standalone usage
        $extension = [System.IO.Path]::GetExtension($ComputerListPath).ToLower()
        if ($extension -eq ".csv") {
            $csv = Import-Csv -Path $ComputerListPath
            $computers = @($csv | Where-Object { $_.ComputerName } | ForEach-Object { $_.ComputerName.Trim() })
        }
        else {
            $computers = @(Get-Content -Path $ComputerListPath |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') } |
                ForEach-Object { $_.Trim() })
        }
    }
}
catch {
    $errorMsg = "Failed to load computer list: $_"
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if ($computers.Count -eq 0) {
    $errorMsg = "No computers found in $ComputerListPath"
    if (Test-LoggingEnabled) { Write-Log $errorMsg -Level Error }
    throw $errorMsg
}

if (Test-LoggingEnabled) {
    Write-Log "Loaded $($computers.Count) computers from list" -Level Info
}

# Display banner
if (Get-Command Write-Banner -ErrorAction SilentlyContinue) {
    Write-Banner -Title "GA-AppLocker Event Collection" -Subtitle "Collecting events from $($computers.Count) computers"
} else {
    Write-Host "=== GA-AppLocker Event Collection ===" -ForegroundColor Cyan
    Write-Host "Collecting events from $($computers.Count) computers..." -ForegroundColor Cyan
    Write-Host ""
}
Write-Host "Results will be saved to: $outputRoot" -ForegroundColor Gray
if ($SinceLastRun -and $lastRunTime) {
    Write-Host "Collection mode: Incremental (since $($lastRunTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor Cyan
} else {
    Write-Host "Days back: $(if ($DaysBack -eq 0) { 'All available' } else { $DaysBack })" -ForegroundColor Gray
}
Write-Host "Event types: $(if ($BlockedOnly) { 'Blocked only' } elseif ($IncludeAllowedEvents) { 'All audit events' } else { 'Blocked only (default)' })" -ForegroundColor Gray

# Results collection
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$allBlockedEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

# Clean up old jobs
$oldJobs = Get-Job -Name "EventCollect-*" -ErrorAction SilentlyContinue
if ($oldJobs) {
    Write-Host "Cleaning up $($oldJobs.Count) leftover jobs..." -ForegroundColor Yellow
    $oldJobs | Remove-Job -Force -ErrorAction SilentlyContinue
}

# Extract credential components for job
$credUsername = $Credential.UserName
$credPassword = $Credential.Password

# Extract DC credential components if provided
$dcCredUsername = if ($DCCredential) { $DCCredential.UserName } else { $null }
$dcCredPassword = if ($DCCredential) { $DCCredential.Password } else { $null }

# Try to identify Domain Controllers from AD if available
$domainControllers = @()
try {
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        $domainControllers = @((Get-ADDomainController -Filter *).HostName)
        if ($domainControllers.Count -gt 0) {
            Write-Host "Detected $($domainControllers.Count) Domain Controller(s)" -ForegroundColor Cyan
            if ($DCCredential) {
                Write-Host "DC credentials will be used for: $($domainControllers -join ', ')" -ForegroundColor Cyan
            }
        }
    }
}
catch {
    # AD module not available or not domain joined - continue without DC detection
}

# Calculate start date for event query
# Priority: SinceLastRun (if valid) > DaysBack > All available
$startDate = if ($SinceLastRun -and $lastRunTime) {
    # Use last run time for incremental collection
    $lastRunTime
} elseif ($DaysBack -gt 0) {
    (Get-Date).AddDays(-$DaysBack)
} else {
    [DateTime]::MinValue
}
$startDateStr = $startDate.ToString("o")

# Track the collection start time (for saving state later)
$collectionStartTime = Get-Date

# Determine which event IDs to collect
# Blocked events: 8004 (EXE/DLL), 8006 (MSI/Script), 8008 (Packaged app)
# Allowed events: 8003 (EXE/DLL), 8005 (MSI/Script), 8007 (Packaged app)
$collectAllowed = $IncludeAllowedEvents -and -not $BlockedOnly

# Process each computer
$jobCount = 0
foreach ($computer in $computers) {
    $jobCount++

    # Determine if this computer is a Domain Controller and select appropriate credentials
    $isDC = $domainControllers | Where-Object { $_ -eq $computer -or $_ -like "$computer.*" }
    $useUsername = $credUsername
    $usePassword = $credPassword

    if ($isDC -and $dcCredUsername -and $dcCredPassword) {
        $useUsername = $dcCredUsername
        $usePassword = $dcCredPassword
        Write-Host "[$jobCount/$($computers.Count)] Starting (DC): $computer" -ForegroundColor Magenta
    }
    else {
        Write-Host "[$jobCount/$($computers.Count)] Starting: $computer" -ForegroundColor Gray
    }

    Start-Job -Name "EventCollect-$computer" -ArgumentList $computer, $useUsername, $usePassword, $outputRoot, $startDateStr, $MaxEventsPerComputer, $collectAllowed -ScriptBlock {
        param($Computer, $UserName, $SecurePass, $OutputRoot, $StartDateStr, $MaxEvents, $CollectAllowed)

        # Reconstruct credential
        $Credential = New-Object System.Management.Automation.PSCredential($UserName, $SecurePass)
        $PSDefaultParameterValues.Clear()

        $startDate = [DateTime]::Parse($StartDateStr)
        $start = Get-Date

        $result = [PSCustomObject]@{
            Computer = $Computer
            Status = "Failed"
            Message = ""
            StartTime = $start
            EndTime = $null
            BlockedCount = 0
            AllowedCount = 0
            UniqueApps = 0
        }

        $blockedEvents = @()
        $allowedEvents = @()

        try {
            # Create session
            $session = New-PSSession -ComputerName $Computer -Credential $Credential -Authentication Default -ErrorAction Stop

            # Create output folder
            $computerFolder = Join-Path $OutputRoot $Computer
            New-Item -ItemType Directory -Path $computerFolder -Force | Out-Null

            # Collect events from remote computer
            $eventData = Invoke-Command -Session $session -ArgumentList $startDate, $MaxEvents, $CollectAllowed -ScriptBlock {
                param($StartDate, $MaxEvents, $CollectAllowed)

                $blockedIds = @(8004, 8006, 8008)
                $allowedIds = @(8003, 8005, 8007)

                # AppLocker event log names
                $logNames = @(
                    'Microsoft-Windows-AppLocker/EXE and DLL',
                    'Microsoft-Windows-AppLocker/MSI and Script',
                    'Microsoft-Windows-AppLocker/Packaged app-Execution'
                )

                $blocked = @()
                $allowed = @()

                foreach ($logName in $logNames) {
                    try {
                        # Check if log exists
                        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
                        if (-not $log) { continue }

                        # Build filter for blocked events
                        $blockedFilter = @{
                            LogName = $logName
                            Id = $blockedIds
                        }
                        if ($StartDate -ne [DateTime]::MinValue) {
                            $blockedFilter.StartTime = $StartDate
                        }

                        $events = Get-WinEvent -FilterHashtable $blockedFilter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

                        foreach ($event in $events) {
                            # Parse event XML for detailed info
                            $xml = [xml]$event.ToXml()
                            $eventData = $xml.Event.EventData.Data

                            # Extract fields from event data
                            $filePath = ($eventData | Where-Object { $_.Name -eq 'FilePath' }).'#text'
                            $fileHash = ($eventData | Where-Object { $_.Name -eq 'FileHash' }).'#text'
                            $fqbn = ($eventData | Where-Object { $_.Name -eq 'Fqbn' }).'#text'  # Fully Qualified Binary Name
                            $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUser' }).'#text'
                            $policyName = ($eventData | Where-Object { $_.Name -eq 'PolicyName' }).'#text'

                            # Parse publisher info from FQBN (format: O=Publisher, L=..., S=..., C=...\ProductName\Version\FileName)
                            $publisher = ""
                            $productName = ""
                            $fileVersion = ""
                            if ($fqbn -and $fqbn -ne "-") {
                                if ($fqbn -match "^O=([^\\,]+)") {
                                    $publisher = $matches[1].Trim('"')
                                }
                                $parts = $fqbn -split '\\'
                                if ($parts.Count -ge 3) {
                                    $productName = $parts[-3]
                                    $fileVersion = $parts[-2]
                                }
                            }

                            $blocked += [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                EventId = $event.Id
                                EventType = "Blocked"
                                FilePath = $filePath
                                FileName = if ($filePath) { Split-Path $filePath -Leaf } else { "" }
                                FileHash = $fileHash
                                Publisher = $publisher
                                ProductName = $productName
                                FileVersion = $fileVersion
                                FQBN = $fqbn
                                TargetUser = $targetUser
                                PolicyName = $policyName
                                LogName = $logName
                            }
                        }

                        # Collect allowed events if requested
                        if ($CollectAllowed) {
                            $allowedFilter = @{
                                LogName = $logName
                                Id = $allowedIds
                            }
                            if ($StartDate -ne [DateTime]::MinValue) {
                                $allowedFilter.StartTime = $StartDate
                            }

                            $allowEvents = Get-WinEvent -FilterHashtable $allowedFilter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

                            foreach ($event in $allowEvents) {
                                $xml = [xml]$event.ToXml()
                                $eventData = $xml.Event.EventData.Data

                                $filePath = ($eventData | Where-Object { $_.Name -eq 'FilePath' }).'#text'
                                $fileHash = ($eventData | Where-Object { $_.Name -eq 'FileHash' }).'#text'
                                $fqbn = ($eventData | Where-Object { $_.Name -eq 'Fqbn' }).'#text'
                                $targetUser = ($eventData | Where-Object { $_.Name -eq 'TargetUser' }).'#text'
                                $policyName = ($eventData | Where-Object { $_.Name -eq 'PolicyName' }).'#text'

                                $publisher = ""
                                $productName = ""
                                $fileVersion = ""
                                if ($fqbn -and $fqbn -ne "-") {
                                    if ($fqbn -match "^O=([^\\,]+)") {
                                        $publisher = $matches[1].Trim('"')
                                    }
                                    $parts = $fqbn -split '\\'
                                    if ($parts.Count -ge 3) {
                                        $productName = $parts[-3]
                                        $fileVersion = $parts[-2]
                                    }
                                }

                                $allowed += [PSCustomObject]@{
                                    TimeCreated = $event.TimeCreated
                                    EventId = $event.Id
                                    EventType = "Allowed"
                                    FilePath = $filePath
                                    FileName = if ($filePath) { Split-Path $filePath -Leaf } else { "" }
                                    FileHash = $fileHash
                                    Publisher = $publisher
                                    ProductName = $productName
                                    FileVersion = $fileVersion
                                    FQBN = $fqbn
                                    TargetUser = $targetUser
                                    PolicyName = $policyName
                                    LogName = $logName
                                }
                            }
                        }
                    }
                    catch {
                        # Log might not exist or be accessible - skip to next log
                        continue
                    }
                }

                return @{
                    Blocked = $blocked
                    Allowed = $allowed
                }
            }

            # Process results
            if ($eventData) {
                $blockedEvents = $eventData.Blocked
                $allowedEvents = $eventData.Allowed

                # Export blocked events
                if ($blockedEvents -and $blockedEvents.Count -gt 0) {
                    $blockedEvents | Export-Csv -Path (Join-Path $computerFolder "BlockedEvents.csv") -NoTypeInformation
                    $result.BlockedCount = $blockedEvents.Count

                    # Create unique apps summary for rule creation
                    $uniqueApps = $blockedEvents |
                        Where-Object { $_.FilePath } |
                        Group-Object FilePath |
                        ForEach-Object {
                            $first = $_.Group[0]
                            [PSCustomObject]@{
                                FilePath = $first.FilePath
                                FileName = $first.FileName
                                Publisher = $first.Publisher
                                ProductName = $first.ProductName
                                FileVersion = $first.FileVersion
                                FileHash = $first.FileHash
                                FQBN = $first.FQBN
                                OccurrenceCount = $_.Count
                                FirstSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                                LastSeen = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                                Users = (($_.Group | Select-Object -ExpandProperty TargetUser -Unique) -join "; ")
                            }
                        } |
                        Sort-Object OccurrenceCount -Descending

                    if ($uniqueApps.Count -gt 0) {
                        $uniqueApps | Export-Csv -Path (Join-Path $computerFolder "UniqueBlockedApps.csv") -NoTypeInformation
                        $result.UniqueApps = $uniqueApps.Count
                    }
                }

                # Export allowed events
                if ($allowedEvents -and $allowedEvents.Count -gt 0) {
                    $allowedEvents | Export-Csv -Path (Join-Path $computerFolder "AllowedEvents.csv") -NoTypeInformation
                    $result.AllowedCount = $allowedEvents.Count
                }

                # Create event summary
                $summary = @(
                    [PSCustomObject]@{ EventType = "Blocked (8004/8006/8008)"; Count = $result.BlockedCount }
                    [PSCustomObject]@{ EventType = "Allowed (8003/8005/8007)"; Count = $result.AllowedCount }
                    [PSCustomObject]@{ EventType = "Unique Blocked Apps"; Count = $result.UniqueApps }
                )
                $summary | Export-Csv -Path (Join-Path $computerFolder "EventSummary.csv") -NoTypeInformation
            }

            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            $result.Status = "Success"
        }
        catch {
            $result.Message = $_.Exception.Message
            if ($null -ne $session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }
        finally {
            $result.EndTime = Get-Date
        }

        return @{
            Result = $result
            BlockedEvents = $blockedEvents
        }
    } -ErrorAction SilentlyContinue | Out-Null

    # Throttle
    $runningJobs = Get-Job -Name "EventCollect-*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    while ($runningJobs.Count -ge $ThrottleLimit) {
        Start-Sleep -Seconds 2
        $runningJobs = Get-Job -Name "EventCollect-*" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }
    }
}

# Wait for completion
Write-Host "`nWaiting for event collection to complete..." -ForegroundColor Yellow

$allJobs = Get-Job -Name "EventCollect-*" -ErrorAction SilentlyContinue
$spinChars = @('|', '/', '-', '\')
$spinIndex = 0
$startWait = Get-Date

while (($allJobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
    $runningCount = ($allJobs | Where-Object { $_.State -eq 'Running' }).Count
    $completedCount = ($allJobs | Where-Object { $_.State -eq 'Completed' }).Count
    $elapsed = [math]::Round(((Get-Date) - $startWait).TotalMinutes, 1)

    $spin = $spinChars[$spinIndex % 4]
    Write-Host "`r  [$spin] Running: $runningCount | Completed: $completedCount / $($computers.Count) | Elapsed: $elapsed min   " -NoNewline -ForegroundColor Cyan
    $spinIndex++

    Start-Sleep -Seconds 2
    $allJobs = Get-Job -Name "EventCollect-*" -ErrorAction SilentlyContinue
}
Write-Host ""

# Collect results
if ($null -ne $allJobs -and $allJobs.Count -gt 0) {
    foreach ($job in $allJobs) {
        $computerName = $job.Name -replace '^EventCollect-', ''
        try {
            if ($job.State -eq 'Failed') {
                # Extract detailed error info from failed job
                $errorMsg = if ($job.ChildJobs -and $job.ChildJobs[0].JobStateInfo.Reason) {
                    "Remote job failed: $($job.ChildJobs[0].JobStateInfo.Reason.Message)"
                } elseif ($job.JobStateInfo.Reason) {
                    "Job execution failed: $($job.JobStateInfo.Reason.Message)"
                } else {
                    "Job failed to execute (no error details available - check WinRM connectivity)"
                }
                $results.Add([PSCustomObject]@{
                    Computer = $computerName
                    Status = "Failed"
                    Message = $errorMsg
                    StartTime = $null
                    EndTime = Get-Date
                    BlockedCount = 0
                    AllowedCount = 0
                    UniqueApps = 0
                })
            }
            else {
                $jobOutput = Receive-Job -Job $job -ErrorAction SilentlyContinue
                if ($null -ne $jobOutput) {
                    $results.Add($jobOutput.Result)

                    # Collect blocked events for consolidated output
                    if ($jobOutput.BlockedEvents -and $jobOutput.BlockedEvents.Count -gt 0) {
                        foreach ($evt in $jobOutput.BlockedEvents) {
                            $allBlockedEvents.Add([PSCustomObject]@{
                                Computer = $computerName
                                TimeCreated = $evt.TimeCreated
                                EventId = $evt.EventId
                                FilePath = $evt.FilePath
                                FileName = $evt.FileName
                                FileHash = $evt.FileHash
                                Publisher = $evt.Publisher
                                ProductName = $evt.ProductName
                                FileVersion = $evt.FileVersion
                                FQBN = $evt.FQBN
                                TargetUser = $evt.TargetUser
                                PolicyName = $evt.PolicyName
                                LogName = $evt.LogName
                            })
                        }
                    }
                }
                else {
                    $results.Add([PSCustomObject]@{
                        Computer = $computerName
                        Status = "Failed"
                        Message = "No result returned"
                        StartTime = $null
                        EndTime = Get-Date
                        BlockedCount = 0
                        AllowedCount = 0
                        UniqueApps = 0
                    })
                }
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Computer = $computerName
                Status = "Failed"
                Message = $_.Exception.Message
                StartTime = $null
                EndTime = Get-Date
                BlockedCount = 0
                AllowedCount = 0
                UniqueApps = 0
            })
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

# Export consolidated results
$logPath = Join-Path $outputRoot "EventCollectionResults.csv"
$results | Export-Csv -Path $logPath -NoTypeInformation

# Export all blocked events (consolidated)
if ($allBlockedEvents.Count -gt 0) {
    $allBlockedPath = Join-Path $outputRoot "AllBlockedEvents.csv"
    $allBlockedEvents | Export-Csv -Path $allBlockedPath -NoTypeInformation

    # Create consolidated unique apps for rule creation
    $consolidatedUnique = $allBlockedEvents |
        Where-Object { $_.FilePath } |
        Group-Object FilePath |
        ForEach-Object {
            $first = $_.Group[0]
            [PSCustomObject]@{
                FilePath = $first.FilePath
                FileName = $first.FileName
                Publisher = $first.Publisher
                ProductName = $first.ProductName
                FileVersion = $first.FileVersion
                FileHash = $first.FileHash
                FQBN = $first.FQBN
                TotalOccurrences = $_.Count
                ComputersAffected = (($_.Group | Select-Object -ExpandProperty Computer -Unique) -join "; ")
                ComputerCount = ($_.Group | Select-Object -ExpandProperty Computer -Unique).Count
                Users = (($_.Group | Select-Object -ExpandProperty TargetUser -Unique) -join "; ")
                FirstSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
                LastSeen = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            }
        } |
        Sort-Object TotalOccurrences -Descending

    $uniquePath = Join-Path $outputRoot "UniqueBlockedApps.csv"
    $consolidatedUnique | Export-Csv -Path $uniquePath -NoTypeInformation
}

# Summary
$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$totalBlocked = ($results | Measure-Object -Property BlockedCount -Sum).Sum
$totalAllowed = ($results | Measure-Object -Property AllowedCount -Sum).Sum
$totalUniqueApps = $consolidatedUnique.Count

Write-Host "`n=== Event Collection Complete ===" -ForegroundColor Green
Write-Host "Computers processed: $($results.Count)" -ForegroundColor Cyan
Write-Host "  Success: $successCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Events collected:" -ForegroundColor Cyan
Write-Host "  Blocked events: $totalBlocked" -ForegroundColor Yellow
Write-Host "  Allowed events: $totalAllowed" -ForegroundColor Gray
Write-Host "  Unique blocked apps: $totalUniqueApps" -ForegroundColor Yellow
Write-Host ""
Write-Host "Results saved to: $outputRoot" -ForegroundColor Cyan

# Save state for incremental collection (only if at least one success)
if ($SinceLastRun -or $successCount -gt 0) {
    try {
        $stateData = @{
            LastSuccessfulRun = $collectionStartTime.ToString("o")
            ComputersProcessed = $results.Count
            SuccessCount = $successCount
            TotalBlocked = $totalBlocked
            OutputPath = $outputRoot
        }
        $stateData | ConvertTo-Json | Out-File -FilePath $StateFilePath -Encoding UTF8 -Force
        if ($SinceLastRun) {
            Write-Host "State saved for next incremental run: $StateFilePath" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not save state file: $_"
    }
}

# Show failures
$failures = $results | Where-Object { $_.Status -eq "Failed" }
if ($failures.Count -gt 0) {
    Write-Host "`nFailed computers:" -ForegroundColor Yellow
    foreach ($f in $failures) {
        Write-Host "  $($f.Computer): $($f.Message)" -ForegroundColor Red
    }
}

# Show top blocked apps
if ($consolidatedUnique -and $consolidatedUnique.Count -gt 0) {
    Write-Host "`nTop 10 blocked applications:" -ForegroundColor Yellow
    $top10 = $consolidatedUnique | Select-Object -First 10
    foreach ($app in $top10) {
        $name = if ($app.Publisher) { "$($app.FileName) ($($app.Publisher))" } else { $app.FileName }
        Write-Host "  $($app.TotalOccurrences.ToString().PadLeft(5)) x $name" -ForegroundColor White
        Write-Host "         Path: $($app.FilePath)" -ForegroundColor DarkGray
    }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Review UniqueBlockedApps.csv to identify apps needing rules" -ForegroundColor White
Write-Host "  2. Import blocked apps to a software list for rule generation" -ForegroundColor White
Write-Host "  3. Generate policy rules: .\Start-AppLockerWorkflow.ps1 -> [S] Software" -ForegroundColor White

# Finalize logging
if (Test-LoggingEnabled) {
    Write-LogSection "Event Collection Summary"
    Write-Log "Computers processed: $($results.Count)" -Level Info
    Write-Log "Success: $successCount" -Level Success
    Write-Log "Failed: $failCount" -Level $(if ($failCount -gt 0) { "Warning" } else { "Info" })
    Write-Log "Blocked events: $totalBlocked" -Level Info
    Write-Log "Allowed events: $totalAllowed" -Level Info
    Write-Log "Unique blocked apps: $totalUniqueApps" -Level Info
    Write-Log "Output path: $outputRoot" -Level Info

    # Log results with per-computer details
    Write-LogResults -Results $results

    $logFile = Stop-Logging -Summary "Collected events from $($results.Count) computers, $totalBlocked blocked events, $totalUniqueApps unique apps"
    Write-Host "Log file: $logFile" -ForegroundColor Gray
}

# Return output path for workflow chaining
return $outputRoot
